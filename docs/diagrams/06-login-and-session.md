# 06 Login, session, and abuse controls

## Login request

Cheap checks run first. The expensive Argon2id hash runs last.

```mermaid
flowchart TD
    S(["POST login"]) --> RL{"IP rate limit passed?"}
    RL -- No --> T1["429 Too Many Requests"]
    RL -- Yes --> CS{"Anti-forgery token valid?"}
    CS -- No --> T2["400 Bad Request"]
    CS -- Yes --> CC{"Concurrent hash limit passed?"}
    CC -- No --> T4["503 Retry later"]
    CC -- Yes --> LU["Load user by tenant and email"]
    LU --> TH{"Wait running for this account and source?"}
    TH -- Yes --> T3["Argon2id against the dummy hash, generic failure"]
    TH -- No --> HV["Argon2id verify (dummy hash if user is unknown)"]
    HV --> OK{"Password correct and user active?"}
    OK -- No --> F["Generic failure, count failure for account and source, audit event"]
    OK -- Yes --> LS{"Live session of this user in the session list?"}
    LS -- Yes --> RA["Same session and sid, new session ID"]
    LS -- No --> FL{"Five live sessions in the list?"}
    FL -- Yes --> SL["Refuse: session_limit"]
    FL -- No --> NS["New session, new sid, new session ID"]
    RA --> CK["Set cookie with the session list, audit event"]
    NS --> CK
```

Failure responses and timing are the same for an unknown user and a wrong password (D5).

## Session cookie

```mermaid
flowchart LR
    CK["Cookie __Host-Heimdall.Session: 1 to 5 random 256-bit IDs, Secure, HttpOnly, SameSite=Lax, no Domain"]
    SV[("sessions table: hash of each ID")]
    CK -->|"hash each ID, one query for each request"| SV
    SV --> CH{"Not revoked, idle limit and absolute limit not passed, created after password change?"}
    CH -- Yes --> OK["Valid session"]
    CH -- No --> NO["Show login page"]
```

## Abuse control layers

Throttle. Do not hard-lock accounts. A lock lets an attacker deny service to a victim.

```mermaid
flowchart TB
    L1["Layer 1: IP rate limit (cheap, first)"]
    L2["Layer 2: backoff for each account and source (delay doubles with failures, never a lock)"]
    L3["Layer 3: challenge after repeated failures (Phase 2)"]
    L4["Layer 4: temporary IP block on strong signals (Phase 2)"]
    L5["Layer 5: alert on credential stuffing patterns (Phase 2)"]
    L1 --> L2 --> L3 --> L4 --> L5
```

## Consent and CSRF

```mermaid
sequenceDiagram
    autonumber
    participant B as Browser
    participant H as Heimdall
    participant DB as PostgreSQL

    B->>H: GET /authorize
    H->>DB: Store authorization request R (checked parameters)
    H->>B: 302 to /consent?request_id=R
    B->>H: GET /session/v1/consent?request_id=R
    H->>B: Client name, scopes, redirect host (from R and the client registration)
    B->>H: POST /session/v1/consent (JSON: request ID R, decision; antiforgery header; Origin)
    H->>DB: Load R, store the decision and the user on R
    B->>H: GET /oauth/v1/authorize/resume?request_id=R
    H->>DB: Decision of this user: approve inserts the code, deny deletes R
    H->>B: Redirect to redirect_uri (code, or error=access_denied)
```
