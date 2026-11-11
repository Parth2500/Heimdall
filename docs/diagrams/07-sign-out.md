# Sign-out

The design is D29 to D35 in `docs/threat-model.md` and U17 in `docs/frontend-design.md`. The statements are in `docs/schema-design.md` ("End a session", "Deliver a back-channel logout").

## RP-initiated logout

```mermaid
sequenceDiagram
    autonumber
    participant B as Browser
    participant C as Client app
    participant H as Heimdall
    participant P as Account pages
    participant DB as PostgreSQL

    C->>B: 302 /oauth/v1/logout?id_token_hint&post_logout_redirect_uri&state
    B->>H: GET /oauth/v1/logout (session cookie)
    H->>H: Check the hint: RS256, typ JWT, kid in the JWKS, iss, one aud of the tenant. exp does not count (D30).
    H->>H: Check the URI: registered for that client, exact match (D32).
    alt No valid session
        H->>B: 302 to the URI with state, or the signed-out page
    else Hint sid = this session's sid (D31)
        H->>DB: One transaction: end the session, revoke its families, queue the logouts (D33)
        H->>B: 302 to the URI with state. The cookie stays (D55).
    else Any other request (no hint, an old hint, a forged hint)
        H->>B: 302 /account/logout?logout_request=sealed target (U17)
        B->>P: GET /account/logout
        P->>B: "Sign out of Heimdall?" Nothing ends yet.
        B->>H: POST /session/v1/logout {logout_request} with antiforgery, Origin, JSON
        H->>H: Open the sealed value. Check the client and the URI again.
        H->>DB: The same transaction (D33)
        H->>B: 200 {redirect_to}. The cookie stays (D55).
        B->>C: GET the URI with state, or the signed-out page
    end
```

A cross-site page can send the browser to `/oauth/v1/logout`, but it cannot get the ID token of this session. So it reaches only the confirm page (logout CSRF).

## Back-channel delivery

```mermaid
sequenceDiagram
    autonumber
    participant J as BackchannelLogoutJob (each server)
    participant DB as PostgreSQL
    participant K as Key store
    participant S as Client server

    loop Every 5 seconds
        J->>DB: UPDATE ... attempts + 1, next_attempt_at = now + lease ... FOR UPDATE SKIP LOCKED RETURNING *
        par For each row
            J->>K: Sign logout_token: typ logout+jwt, aud client_id, sub, sid, jti, events, exp = iat + 2 min
            J->>J: Resolve the host. Refuse any internal address (D35, outside Development).
            J->>S: POST backchannel_logout_uri, logout_token=... (5 s limit, no redirect)
            S-->>J: 200 (no body is read)
        end
        alt 2xx
            J->>DB: DELETE the row
        else Failure, fewer than 5 retries
            J->>DB: next_attempt_at = now + 30 s × 2^(attempts - 1)
        else Failure after the 5th retry
            J->>DB: DELETE the row, audit backchannel_logout.dropped
        end
    end
```

## What ends, and when

```mermaid
flowchart LR
    S[Sign-out] --> T[(One transaction)]
    T --> A[sessions.revoked_at]
    T --> F[Every family with the sid<br/>revoked_reason = user_logout<br/>offline_access too]
    T --> Q[backchannel_logouts rows]
    F --> R[Refresh tokens: invalid_grant at once]
    F --> I[Access tokens: valid offline until exp, at most 5 minutes]
    F --> U[/userinfo and introspection: invalid_token at once]
    Q --> D[Client servers end their own sessions]
```
