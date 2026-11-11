# Heimdall Threat Model (Phase 0)

Method: STRIDE for each trust boundary. References: RFC 6749, RFC 7636 (PKCE), RFC 7009 (revocation), RFC 9700 (OAuth Security BCP), RFC 9207 (issuer identification), OAuth 2.1 draft.

Writing rules are in `CLAUDE.md`. They follow ASD-STE100 style, applied by hand.

## Glossary

Each term has one meaning in this document. Do not use a synonym.

| Term | Meaning |
|---|---|
| Heimdall | This identity provider. It is also the issuer. |
| Tenant | An isolated domain with its own users, clients, keys, and settings. One Heimdall installation can host many tenants. |
| Client | An application that asks Heimdall for tokens. A client belongs to exactly one tenant. |
| Public client | A client that cannot keep a secret (single-page app, mobile app). |
| Confidential client | A client that can keep a secret (server application). |
| Client assertion | A JWT that a confidential client signs with its private key to authenticate (`private_key_jwt`, RFC 7523). It works once. |
| Resource server | An API that accepts Heimdall access tokens. |
| Audience | The resource server that a token is for. It is the `aud` claim. A client asks for one with the `resource` parameter (RFC 8707). |
| Subject | The user that an access token or ID token identifies. |
| Code | An authorization code. It is single-use and short-lived. |
| Redeem | To exchange a code for tokens at `/token`. |
| Access token | A short-lived JWT that a client sends to a resource server. |
| Refresh token | An opaque token that a client exchanges for new tokens. |
| Family | All refresh tokens that come from one code redemption. Each family has one `TokenFamilyId`. |
| Rotate | To replace a refresh token with a new one each time the client uses it. |
| Key rotation | To replace a tenant's active signing key with the next key on a schedule. The old key stays in the JWKS until its last token expires. |
| Reuse | A second use of a code or refresh token that is already used. |
| Revoke | To make a token or family permanently invalid. |
| Bearer | A token that gives access to anyone who holds it. |
| DPoP | Demonstrating Proof of Possession (RFC 9449). The client holds a private key and signs a DPoP proof for each request. |
| DPoP proof | A short JWT that the client signs for one request. It names the HTTP method and URL, and it carries the client's public key. |
| Key thumbprint | The RFC 7638 SHA-256 thumbprint of the client's public key, in base64url. A bound token carries it as `cnf.jkt`. |
| Bound token | A token that works only with a DPoP proof from one key. It is the opposite of a bearer token. |
| PKCE | Proof Key for Code Exchange. It binds a code to the client that asked for it. |
| Verifier, challenge | The `code_verifier` is a secret from the client. The `code_challenge` is its SHA-256 hash. |
| JWKS | The public key set that Heimdall publishes. Resource servers use it to check signatures. |
| `kid` | The key identifier. It tells a verifier which key in the JWKS signed a token. Heimdall uses the RFC 7638 thumbprint of the public key. |
| Key store | The component that holds the private signing keys and signs with them. The keys never leave it. Key Vault or KMS on deployment. A local file in development. |
| Hash | A one-way digest of a secret. Heimdall stores hashes, not secrets. |
| Throttle | To slow or limit requests. It does not lock out the caller. |
| Audit log | An append-only record of security events. |
| Protocol rejection | Heimdall refuses a request before the grant runs, because the request breaks the HTTP or OAuth format. Heimdall logs it. |
| Account pages | The Angular login, consent, error, and signed-out pages. Heimdall serves them on each tenant origin under `/account/`. |
| Demo SPA | A sample Angular client on its own origin. It signs in with Heimdall as a public client. |
| Client origin | The origin (scheme, host, and port) of an `https` redirect URI of an active public client. A browser page on a client origin may read the responses of `/token`, `/revoke`, and `/userinfo` (D23). |
| CSP nonce | A random value that Heimdall creates for each page response. Only script and style elements that carry it can run. |
| Backend-for-frontend (BFF) | A server part of a browser app. It keeps the tokens, and the browser gets only a cookie. |
| Session | One sign-in of one user in one browser. It has one cookie secret (the session ID) and one public `sid`. |
| Session list | The sessions that one browser's cookie names. At most five. |
| Live session | A session that passes every validity rule: not revoked, the tenant and the user match, the user is active, and no limit has passed. |
| Ended session | A session that is not live. |
| Grant rejection | The grant refuses a well-formed request, for example for a wrong secret or a scope that is not allowed. Heimdall audits it. |

## Trust boundaries

| # | Boundary | Other side | Trust level |
|---|---|---|---|
| B1 | User agent <-> Heimdall | Browser. It can have malicious extensions. A client can have XSS. | Untrusted |
| B2 | Client <-> Heimdall | Registered clients. A client can be compromised or impersonated. | Untrusted until authenticated. Public clients are never authenticated. |
| B3 | Heimdall <-> Postgres | Persistence | Trusted. Assume a read-only leak is possible (backup, SQL injection). |
| B4 | Heimdall <-> key store | Signing keys. A file or database now. Key Vault or KMS on deployment. | Highest-value asset |
| B5 | Resource server <-> Heimdall | Anyone on the internet. Requests are unauthenticated reads (JWKS). | Untrusted |

## Cross-cutting decisions

These decisions apply to every endpoint. The tables below refer to them by ID.

| ID | Decision | Reason |
|---|---|---|
| D1 | Use TLS only. Set HSTS on the issuer origin. | Every secret in OAuth is a bearer value on the network. |
| D2 | Require PKCE with `S256` for all clients. Reject `plain`. | This is OAuth 2.1. A stolen code is useless without the verifier. |
| D3 | Store codes, refresh tokens, and client secrets as hashes only. Generate each with 256 bits of randomness. Use SHA-256. Use Argon2id for user passwords only. | A leak of the database must not give an attacker usable credentials. Random 256-bit values do not need a slow hash. |
| D4 | Compare secrets with `CryptographicOperations.FixedTimeEquals` on the hashes. | This removes the timing side channel. |
| D5 | Return the same error for each failure of one kind. Return `invalid_client` for an unknown client or a wrong secret. Return `invalid_grant` for an unknown, expired, used, or mismatched code or refresh token. Write the real reason to the audit log only. | An attacker cannot learn which part was wrong. |
| D6 | Send `Cache-Control: no-store` and `Pragma: no-cache` on token responses. | RFC 6749, section 5.1. |
| D7 | Never log secrets, codes, verifiers, refresh tokens, or client assertions. Log a correlation ID. | Logs are widely readable and kept for a long time. |
| D8 | Sign access tokens as JWTs with `RS256` only. Do not negotiate `alg`. Put `kid` in the header. Set the lifetime to 5 minutes. Make refresh tokens opaque. | A short lifetime limits the damage from theft. A fixed `alg` stops `none` and HS256 confusion attacks. |
| D9 | Add `iss` to the authorization response (RFC 9207). | This stops mix-up attacks. |
| D10 | Confidential clients use `client_secret_basic` or `private_key_jwt` (D45). Public clients use no authentication and PKCE. Changed on 2026-10-28 (DR-011): version 1 had `client_secret_basic` only. | Start with the smallest correct surface. Add the key method when a client needs it. |
| D22 | Each client has a list of allowed audiences. A token has exactly one audience. The client names it with the `resource` parameter (RFC 8707). If the client has only one audience, that audience is the default. An unknown resource returns `invalid_target`. A token from a user's grant can also name the tenant's userinfo endpoint. That endpoint is the default for a client with no audience. A `client_credentials` token never names it. | A token for one API cannot be replayed at another API. A resource server cannot use its token to read user claims at `/userinfo`. |
| D23 | CORS allows a cross-origin read of `/token`, `/revoke`, and `/userinfo` only from a client origin of the tenant. Heimdall echoes that one origin and never sends `*` or `Access-Control-Allow-Credentials`. Discovery and JWKS allow any origin. Every other path, the session API included, sends no CORS header. | A public SPA must read token responses. A wider list would let any page read responses for a stolen code or token. |
| D24 | DPoP is optional for each request. A client registered with `dpop_bound_access_tokens` must send a DPoP proof at `/token`. A valid proof binds the access token (`cnf.jkt`, `token_type` `DPoP`). For a public client, the proof also binds the family: each refresh needs a proof from the same key. Refresh tokens of a confidential client are not bound. | Existing clients keep working, and a client that asks for DPoP cannot be downgraded. A stolen refresh token of a public client is useless without the private key. A confidential client already authenticates (RFC 9449, section 5). |
| D25 | A DPoP proof has `typ` `dpop+jwt` and `alg` `ES256` or `RS256`. The `jwk` header is a public key only: EC P-256, or RSA with at least 2048 bits. The signature must verify with that key. `htm` equals the request method. `htu` equals the endpoint URL without query and fragment. `iat` is at most 60 seconds from the server time. At a resource, `ath` is the hash of the access token. | These are the checks of RFC 9449, section 4.3. A fixed list of algorithms stops `none` and HMAC confusion, as D8 does for Heimdall's own tokens. |
| D26 | Heimdall stores a hash of each proof's key thumbprint and `jti` with one atomic `INSERT`, under a unique index on tenant and hash. A second use fails with `invalid_dpop_proof`. The purge job deletes a row after its window ends. Version 1 has no server nonce (`DPoP-Nonce`). | A replayed proof fails on every server. A nonce adds a round trip, and it mainly helps clients with a wrong clock. It can come later. |
| D27 | `/authorize` accepts `dpop_jkt` (RFC 9449, section 10). A malformed value gets `invalid_request`. Heimdall stores it with the request and the code. The code then needs a proof from that key. The key check is in the redemption statement, so a request without the key does not use up the code. A missing proof gets `invalid_dpop_proof`. A proof from another key gets `invalid_grant`. | The whole flow, from the first redirect to the refresh token, is bound to one key. |
| D28 | `/userinfo` accepts a bound token only with `Authorization: DPoP` and a valid proof. A bound token sent as `Bearer` fails with `invalid_token`. | A thief cannot use a bound token as a bearer token. Without this rule, the binding does nothing. |

## Sign-out: `/oauth/v1/logout` and back-channel logout (issue #40)

Status: proposed on 2026-10-23. The owner reviewed and decided D29 to D35 on 2026-10-26. Built on 2026-10-26: D29 to D35. The confirm page is U17 in `docs/frontend-design.md`.

Boundary: B1 (the browser comes to Heimdall) and a new outbound boundary B6 (Heimdall calls a client's server). The standards are OpenID Connect RP-Initiated Logout 1.0 and OpenID Connect Back-Channel Logout 1.0. Front-channel logout is out of scope, because browsers block third-party cookies in iframes.

Today a session has no public identifier, and a token family does not record the session that created it. So Heimdall cannot end "the tokens of this sign-in", and a client cannot match a logout to its own session. D29 adds that link.

| ID | Decision | Reason |
|---|---|---|
| D29 | Each session gets a public session ID, `sid`: 128 random bits, separate from the cookie secret (D12). The `sid` cannot authenticate anything. The ID token carries it as the `sid` claim. Each code and each token family records the `sid` of the session that created it. Each user access token carries the `fid` claim, which names its token family. The value is opaque and cannot authenticate anything. | The cookie secret, and its hash, must never leave the server. A client needs a value that names the session, to match a back-channel logout. A family needs the link, so that a sign-out ends the tokens of that sign-in. Introspection (#19) must find the family of an access token. The `sid` is not enough, because reuse detection can revoke a family while its session stays active. One migration adds both links. |
| D30 | The `end_session_endpoint` is `/oauth/v1/logout`, for `GET` and `POST`. An `id_token_hint` is valid when Heimdall signed it with a key in the tenant's JWKS (also a retired key), `iss` is the tenant, and `aud` is a client of the tenant. Heimdall ignores `exp`, because a client usually sends an expired ID token at sign-out. A `client_id` parameter must equal `aud` when both are present. | RP-Initiated Logout 1.0, section 2. The signature check stops a forged hint. An expired hint still names the client and the user, and it cannot give access to anything. |
| D31 | Heimdall ends a session at once only when the hint is valid and its `sid` and `sub` name a live session of the browser's session list. Only that session ends. The other accounts of the browser stay signed in. In every other case, a session ends only after the user confirms on a Heimdall page. The confirm page ends one account, named by its `sid`, or every account of the list. The confirm button sends `POST /session/v1/logout`, with the three CSRF layers of the login API. The page gets the checked redirect target only as a sealed value (U17). A `GET` never ends a session without a matching hint. When the browser has no live session, Heimdall has nothing to end. It shows no confirm page and goes on to the redirect step (D32). | Logout CSRF: an attacker's page can send the browser to `/oauth/v1/logout`, but it cannot get the victim's ID token for this session. A hint from an older session does not count, so a leaked old ID token cannot sign the user out without a click. |
| D32 | `post_logout_redirect_uri` must be in the client's registered list, compared by exact match, as for redirect URIs (RFC 9700). The hint or `client_id` names the client. With no client, or an unregistered URI, Heimdall shows its signed-out page and redirects nowhere. Heimdall returns `state` unchanged, at most 512 characters. | An unchecked redirect after sign-out is an open redirect, and phishing pages use it. The signed-out page names no reason, so the endpoint does not show which URIs a client registered. |
| D33 | Ending a session is one transaction: Heimdall sets `revoked_at` on the session, revokes every token family with that `sid` (reason `user_logout`), and queues the back-channel logouts. The session cookie stays: the ended session ID authenticates nothing, and the account picker shows the account as "Signed out" (D55). A sign-out of every account runs this transaction for each session. This includes families with `offline_access`. This differs from Back-Channel Logout 1.0, section 2.7, where such refresh tokens "normally SHOULD NOT be revoked". Access tokens stay valid at a resource server that checks them offline, until `exp` (5 minutes, D8). Heimdall's own `/userinfo` (D44) and introspection (D38) read the family, so they refuse them at once. `/session/v1/logout` uses the same path. | The user asked to sign out, so the refresh tokens of that sign-in end too. One transaction means that no family survives a sign-out half done. Heimdall cannot recall a JWT, and the short lifetime limits the gap. No current client needs access after the user signs out. The owner chose this deviation on 2026-10-26. |
| D34 | A back-channel logout goes to each client that has a family with the session's `sid` and a registered `backchannel_logout_uri`. A redeemed code always has a family. A client with only an unredeemed code has no session to end. The `logout_token` is a JWT with `typ` `logout+jwt`, signed `RS256` with the tenant's active key. It has `iss`, `aud` (the `client_id`), `iat`, `exp` (2 minutes after `iat`), `jti`, `sub`, `sid`, and the back-channel logout event. It has no `nonce`. | Back-Channel Logout 1.0, section 2.4. The `typ` stops a client from taking the token for an ID token. The short lifetime and `jti` let a client refuse a replay. |
| D35 | Heimdall delivers back-channel logouts from an outbox table, in a background job, never in the user's request. It sends one `POST` with a 5-second timeout, follows no redirect, and reads no response body. It retries a failure 5 times with growing waits, then drops it and writes an audit event. A `backchannel_logout_uri` is registered like a redirect URI: absolute, `https` (plain `http` only for a loopback address), no fragment. Outside Development, Heimdall refuses to connect to a loopback, private, or link-local address, checked on the resolved address at connect time. The blocked ranges are `127.0.0.0/8`, `::1`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `100.64.0.0/10`, `169.254.0.0/16`, `fc00::/7`, `fe80::/10`, `0.0.0.0/8`, and the IPv4-mapped IPv6 form of each IPv4 range. The build also blocks multicast (`224.0.0.0/4`, `ff00::/8`), `240.0.0.0/4`, the IETF and documentation ranges (`192.0.0.0/24`, `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`), benchmarking (`198.18.0.0/15`), and, for IPv6, every address outside global unicast (`2000::/3`). Inside it, the build also blocks `2001::/23` (with Teredo), `2001:db8::/32`, 6to4 (`2002::/16`), and `3fff::/20`. So no IPv6 form that can carry an IPv4 address passes: `::/96`, `::ffff:0:0:0/96`, NAT64 (`64:ff9b::/96`, `64:ff9b:1::/48`), 6to4, and Teredo. One blocked address refuses the host. So plain `http` works only in Development. The outbox table is tenant-owned, so it has row-level security and the purge job removes old rows. | A slow or failing client must not slow down or break the user's sign-out. The outbox survives a server restart. The address check at connect time stops server-side request forgery to internal services, also after a DNS change (DNS rebinding). The link-local range includes the cloud metadata address `169.254.169.254`. |

### `GET` and `POST /oauth/v1/logout`

| STRIDE | Threat | Mitigation |
|---|---|---|
| Spoofing | An attacker forges an `id_token_hint` to name a user or a client. | Heimdall checks the signature, `iss`, and `aud` (D30). A forged hint is not valid, so the user must confirm (D31). |
| Tampering | Logout CSRF: an attacker's page sends the victim's browser to the endpoint. | Without a valid hint for this session, the user must confirm with a POST that has the CSRF layers of the login API (D31). |
| Tampering | Open redirect: an attacker sets `post_logout_redirect_uri` to a phishing page. | Exact match against the client's registered list. Otherwise no redirect (D32). |
| Information disclosure | The endpoint shows which URIs or clients exist. | An unregistered URI and an unknown client both get the same signed-out page. |
| Denial of service | A flood of requests to the endpoint uses server resources. | Heimdall applies a rate limit for each IP, as for `/authorize`. |
| Repudiation | A user says they did not sign out. | Heimdall writes `session.revoked` with the reason (`rp_initiated` or `user_confirmed`), the `client_id` of the hint, and the correlation ID. |
| Denial of service | An attacker with an old ID token of the victim signs the victim out. | A hint counts only when its `sid` is the current session (D31). An old hint needs the user's click. |
| Elevation of privilege | Refresh tokens of the session keep working after sign-out. | The same transaction revokes every family with the session's `sid` (D33). |
| Denial of service | The client of one account signs every account of the browser out. | A hint ends only the session that it names (D31). |
| Tampering | A request to the confirm endpoint names the `sid` of a session in another browser. | The `sid` selects only inside the session list of the request's cookie (D29, D31). A `sid` outside the list ends nothing, and a malformed `sid` is refused. |
| Information disclosure | A "Signed out" row shows an email address to the next user of a shared computer. | Accepted by the owner. The row has a "Forget" action, the list ends with the browser, and the row goes after at most 7 days (D55). |
| Information disclosure | Another site reads the account list. | `/session/v1/accounts` sends no CORS header and `no-store`. The cookie is `HttpOnly`. The pages send `frame-ancestors 'none'`. |
| Elevation of privilege | An access token keeps working after sign-out. | It works until `exp`, at most 5 minutes (D8), for a resource server that validates offline. Heimdall cannot recall a JWT. A resource server that needs instant revocation uses introspection, which sees the revoked family at once (D38). |

### Back-channel logout (Heimdall calls the client)

| STRIDE | Threat | Mitigation |
|---|---|---|
| Spoofing | An attacker sends a fake `logout_token` to a client to sign users out. | The token is signed with the tenant's key and has `iss`, `aud`, `exp`, and `jti` (D34). The client guide tells the client to check all of them. |
| Spoofing | A client takes a `logout_token` for an ID token, or the reverse. | `typ` is `logout+jwt`, the token has the logout event and no `nonce`. An ID token has `typ` `JWT`. |
| Tampering | An attacker replays a captured `logout_token`. | The client refuses a `jti` that it has seen, until `exp`. A replay can only repeat the same sign-out. |
| Information disclosure | The `logout_token` reveals more than the client knows. | It has only `sub` and `sid`, which the client already got in the ID token. |
| Denial of service | A slow or dead client endpoint holds up sign-out or fills the outbox. | Delivery is in a background job with a 5-second timeout and 5 retries, then the row is dropped (D35). The user's request never waits. |
| Elevation of privilege | Server-side request forgery: a `backchannel_logout_uri` points at an internal service. | An admin approves the URI at registration. Outside Development, Heimdall refuses loopback, private, and link-local addresses at connect time, and follows no redirect (D35). |

## DPoP proofs (RFC 9449)

The rules are D24 to D28. The table covers the proof itself. The sections for `/token`, the refresh flow, and `/userinfo` refer to it.

| STRIDE | Threat | Mitigation |
|---|---|---|
| Spoofing | An attacker steals a bound access token or refresh token and uses it. | The token works only with a proof signed by the client's private key. A browser client keeps that key non-extractable (WebCrypto). |
| Spoofing | An attacker signs a proof with `alg` `none` or `HS256`, with the public key as the HMAC secret. | Heimdall accepts `ES256` and `RS256` only (D25). It takes the algorithm from its own list, never from the token. |
| Tampering | An attacker captures a proof and replays it, at the same or another server. | Each `jti` works once on every server (D26). `iat` must be recent. `htm` and `htu` bind the proof to one endpoint. |
| Tampering | An attacker puts a private key, or a key with other parameters, in the `jwk` header. | Heimdall refuses a `jwk` with private members, and keys of other types, curves, or sizes (D25). |
| Elevation of privilege | An attacker uses a proof for one access token with another token. | At a resource, `ath` must equal the hash of the presented token (D25). |
| Denial of service | Large or slow proofs cost CPU. | The proof has a size limit. Heimdall checks the format, the header, and the claims before the signature, and the signature before the database. |

## `GET /oauth/v1/authorize` (worked example)

Additional decisions for the account choice (#41). The design note is `docs/account-picker-design.md`.

| ID | Decision | Reason |
|---|---|---|
| D51 | `/authorize` chooses the session of the browser's session list in this order. (1) The user's choice for this request: a selection on the account picker (D52), or the one sign-in after the request was created. (2) `id_token_hint`: the live session of that user (D54). (3) `login_hint`: the live session of the user with that email (D53). (4) No hint: with exactly one live session, Heimdall uses it. An ended session is never a candidate. With several live sessions, or with only ended ones, Heimdall shows the account picker. A selection that no longer names a live session of the list also gives the picker, not another account. With `prompt=none`, Heimdall shows no page: several live sessions become the error `account_selection_required`, and no live session becomes `login_required`. `prompt=select_account` always asks for the user's choice. `prompt=login` with no choice and no hint goes to the sign-in page, not to the picker. The chosen session must also satisfy `prompt=login` and `max_age`. The consent API makes the same choice. | A user's choice wins over a client's hint. One session keeps single sign-on. With several accounts, Heimdall must not guess: a wrong guess signs the user in to a client as the wrong account. OpenID Connect Core, sections 3.1.2.1 and 3.1.2.6, defines the `prompt` values and both error codes. |
| D52 | A selection is one stored value on the authorization request: the `sid` of the chosen session, and the time. Heimdall records it only for a live session of the browser's session list. The resume step checks again that the session is live and in the list. | The choice binds to one request, like a consent decision. The `sid` cannot authenticate anything (D29). Here it only selects inside the list that the cookie authenticated. |
| D53 | `login_hint` is an email address of at most 254 characters. Heimdall ignores any other value. The sign-in page fills the email field with it. With `prompt=none`, a hint for an account that is not signed in and a hint for an account that does not exist give the same `login_required`. | The hint saves typing. An answer about the account would be an enumeration oracle (D5). |
| D55 | The session API gives the account pages the browser's session list: for each session the email, the public `sid`, and the state (signed in or signed out). It never returns a session ID. An ended session stays in the list as "Signed out", also after a user sign-out, until the user forgets it or the purge job deletes the session (7 days after its end). "Forget" removes the ID of an ended session from the cookie. It refuses a live session. The cookie has no `Expires`, so the list ends with the browser. | The owner chose the Entra behavior: the user signs in again without typing the email. The list is readable only with the `HttpOnly` cookie on the tenant origin. "Forget" is the control for a shared computer. A forgotten live session would stay live with no browser that holds its ID, so the user must sign it out first. |
| D54 | An `id_token_hint` at `/authorize` is valid when Heimdall signed it with a key of the tenant, `iss` is the tenant, `aud` is this one client, and `sub` is a user ID. Heimdall ignores `exp`, as in D30. An invalid hint is `invalid_request`. With a valid hint, only a live session of that user gets the code, also after a sign-in as another user or a selection of another account. | OpenID Connect Core, section 3.1.2.1: the client names the user that it expects. A client that renews without a page sends this hint, so that it never gets another account. Heimdall does not continue without a hint that it cannot verify, because the client would then get an account that it did not ask for. |
| STRIDE | Threat | Mitigation |
|---|---|---|
| Spoofing | A rogue client registers a redirect URI that looks like a real one. | Heimdall compares redirect URIs by exact match. It allows no wildcards. An admin must approve each client registration. |
| Tampering | An attacker changes the `code_challenge` on the network. | TLS (D1). PKCE also stops a man-in-the-middle from using a stolen code. |
| Repudiation | A user says they did not grant consent. | Heimdall writes `consent.granted` or `consent.denied` for each decision, with the user, client, scope, IP, and correlation ID. Persisted consent records come in Phase 3. |
| Information disclosure | A code leaks through browser history, the referrer header, or logs. | A code is single-use and expires after 5 minutes. Heimdall never writes a full code to a log (D7). |
| Denial of service | A flood of `/authorize` requests uses all database resources. | Rate limit for each IP and each `client_id`. |
| Elevation of privilege | A client requests more scope than it is allowed. | Heimdall checks the requested scope on the server against the `AllowedScopes` of the client. It refuses extra scope. It does not reduce it. |
| Tampering | Open redirect: an attacker puts an unregistered `redirect_uri` in the link, so an error carries the user to the attacker's site. | Until `client_id` and `redirect_uri` pass the exact-match check, Heimdall shows its own error and never redirects (RFC 6749, section 4.1.2.1). A repeated parameter also gets this error. |
| Spoofing | Mix-up: a client that uses several servers sends a code to the wrong one. | Every redirect from `/authorize` carries `iss`, on success and on error (RFC 9207, D9). |
| Tampering | The browser changes the request between login and the code. | Heimdall stores the checked request. The login page and the resume step get only the request ID. One request gives one code, enforced by the `DELETE` in the code transaction. |
| Spoofing | With several accounts in the browser, a client gets the code of an account that the user did not intend. | Heimdall never guesses between accounts. It uses the user's choice, a valid hint, or the single session (D51). |
| Tampering | An attacker's request names the `sid` of a victim's session as the selection. | A selection counts only for a live session in the session list of the same cookie, checked at the selection and again at the resume step (D52). |
| Repudiation | A user says they did not choose that account. | Heimdall writes `account.selected` with the `sid`, the request, and the correlation ID. |
| Information disclosure | A client learns that the browser holds several accounts, from `account_selection_required`. | Accepted. The answer is one bit, and it goes only to a registered redirect URI of the client. OpenID Connect defines the error for this case. |
| Information disclosure | A client uses `login_hint` to test whether an account exists. | The sign-in page looks the same for every hint, and `prompt=none` gives one error for every hint without a live session (D53). |
| Elevation of privilege | A client sends the `id_token_hint` of another client, or a forged one, to get a user's account. | Heimdall checks the signature, `iss`, and `aud` against this client (D54). The hint only narrows the choice to sessions that this browser already holds. |

## `POST /oauth/v1/token`

Grants: `authorization_code`, `client_credentials`, `refresh_token`. Boundary: B2.

| STRIDE | Threat | Mitigation |
|---|---|---|
| **Spoofing** | An attacker uses a leaked or guessed secret to act as a confidential client. | Heimdall generates the secrets with high entropy and stores hashes (D3). It compares in fixed time (D4). It throttles failures for each `client_id`. During rotation, two secrets are valid at the same time. |
| Spoofing | The `client_credentials` grant has no user and no PKCE. The secret is the only defense. | Heimdall enables this grant for each client separately. A client can use `private_key_jwt` instead of a secret (D45). Heimdall then stores only a public key, so a database leak gives no credential. mTLS is not supported. |
| Spoofing | An attacker claims the `client_id` of a public client. | Heimdall does not authenticate public clients. It binds the code to the client and to the PKCE verifier instead (D2). |
| Spoofing | Confused deputy: an attacker redeems a code that Heimdall issued to a different client. | The stored `client_id` of the code must equal the calling client. The `redirect_uri` must equal the value sent to `/authorize`, if the client sent one. |
| Spoofing | An attacker learns which clients exist from error messages or response time. | Heimdall uses uniform errors (D5). For an unknown `client_id`, it still compares against a dummy hash, so the response time is the same. |
| Spoofing | An attacker replays a stolen refresh token from another machine. | Rotation and family revocation on reuse. See "Refresh flow". With DPoP, a refresh token works only with a proof from the bound key (D24). |
| Spoofing | An attacker poses as Heimdall to the client (mix-up). | TLS and HSTS (D1). The `iss` parameter in the authorization response (D9). |
| **Tampering** | A request repeats a parameter, such as `grant_type`, `code`, or `client_id`. | Heimdall rejects a request with a repeated parameter. It accepts only `application/x-www-form-urlencoded`. |
| Tampering | A client sends credentials in the query string. Proxies and logs capture them. | Heimdall reads parameters from the POST body and the `Authorization` header only. It rejects the query string. |
| Tampering | PKCE downgrade: the challenge uses `plain`, or the verifier is missing. | `/authorize` rejects `plain`. `/token` requires `code_verifier`. It checks that `BASE64URL(SHA256(verifier))` equals the stored challenge, in fixed time. The verifier has 43 to 128 unreserved characters. |
| Tampering | An attacker forges an access token, or uses `alg=none` or HS256 confusion. | Heimdall signs with `RS256` only (D8). The documentation tells resource servers to pin `RS256` too. |
| Tampering | An attacker changes a code or token in the database. | Heimdall stores hashes only. The database enforces a unique `CodeHash` and a non-null `ClientId`. Access to the key store is restricted (B4). |
| **Repudiation** | A client or user denies a redemption or issuance. After a theft, no evidence exists. | Heimdall writes one audit record for each issuance, redemption, grant rejection, and family revocation. The record has: timestamp, `client_id`, subject, grant type, result, source IP, correlation ID. The table is insert-only. The application role has no update or delete right. An immutable store is a Phase 3 item. |
| Repudiation | Malformed requests fill the audit table. Each one costs a database write before any check. | Heimdall logs a protocol rejection and does not audit it. Examples are a query string, a wrong content type, or a repeated parameter. The log line has the error code, the reason, and the correlation ID. It has no parameter value (D7). Decided on 2026-10-18. |
| **Information disclosure** | A browser or proxy caches tokens or secrets. | `no-store` (D6). |
| Information disclosure | Secrets, codes, verifiers, or tokens appear in logs, traces, or exception messages. | D7. Request logging for this route excludes the body and the `Authorization` header. |
| Information disclosure | A database leak (backup, SQL injection) gives an attacker live credentials. | Heimdall stores hashes only (D3). It uses parameterized queries only (EF Core). |
| Information disclosure | An error response shows why a code failed (expired, used, or wrong client). | D5. Only the audit log has the reason. |
| Information disclosure | An access token holds more claims than the resource server needs. | The token holds only `iss`, `sub`, `aud`, `exp`, `iat`, `jti`, `scope`, and `client_id`. Personal data goes only in the ID token and `/userinfo`, and only if the scope allows it. |
| **Denial of service** | A flood of `/token` requests uses all database connections or CPU. | Rate limit for each IP and each `client_id`. Body size limit. Short timeouts. Heimdall rejects malformed requests before any database call. |
| Denial of service | An attacker sends wrong secrets on purpose to lock out a victim client. | Heimdall throttles. It does not lock. The real client stays able to authenticate. |
| Denial of service | Many requests redeem one code at the same time and hold row locks. | One atomic statement: `UPDATE ... WHERE redeemed_at IS NULL AND expires_at > now() RETURNING ...`. A losing request gets zero rows and returns at once. No lock is held for long. |
| **Elevation of privilege** | Two requests redeem the same code at the same time (race). Both get tokens. | The atomic conditional update above, with a unique index on `CodeHash`. A check in application code, followed by an update, is not allowed. |
| Elevation of privilege | An attacker replays a captured code after redemption. | The conditional update affects zero rows on a redeemed code. Heimdall treats this as reuse. It revokes the family that came from that code, writes `code.reuse_detected` and `family.revoked`, and raises an alert (a Critical log line with the event name `SecurityAlert`). It does not revoke all sessions of the user and client pair. |
| Denial of service | An attacker with a stolen code but no verifier tries to burn it, so the real client fails. | The client, the redirect URI, and the PKCE challenge are part of the conditional update. A wrong value matches no row and changes nothing. |
| Elevation of privilege | A client requests a grant it may not use, such as `client_credentials` from a public client. | Each client has an `AllowedGrantTypes` list, checked here. Only confidential clients can use `client_credentials`. |
| Elevation of privilege | A token for one resource server is replayed at another resource server. | Each token has exactly one audience from the client's allowed list (D22). Resource servers check `aud`. |
| Elevation of privilege | A `client_credentials` client requests user scopes such as `openid`. | Heimdall returns `invalid_scope`. A token without a user cannot carry user scopes. |
| Elevation of privilege | A client requests more scope at `/token` than the user approved. | The issued scope is the overlap of the code's approved scope and the client's `AllowedScopes`. Refresh can only reduce scope. |
| Elevation of privilege | A client redeems a code with a different `redirect_uri` or `client_id`. | Heimdall compares with the stored values by exact match. A mismatch returns `invalid_grant` (D5). |

## Refresh flow

Boundary: B2. A refresh token is opaque and single-use. It belongs to a family. The family starts at the code redemption.

| STRIDE | Threat | Mitigation |
|---|---|---|
| Spoofing | An attacker uses a stolen refresh token. | Each use returns a new refresh token and marks the old one as used (`used_at`, and `replaced_by_id` names the next token). Reuse of a used token revokes the whole family at once, in the same transaction as the check. Confidential clients also authenticate. DPoP binds the family of a public client to its key (D24). |
| Spoofing | A client presents a token that Heimdall issued to a different client. | The family's client must equal the calling client. The check is part of the rotation statement, so the wrong client cannot use or burn the token. |
| Tampering | The real client and an attacker present the same token at the same time. Two retries can also cause this. | Rotation is one atomic conditional update on `used_at IS NULL`. One caller wins. Heimdall treats the other caller as reuse. |
| Tampering | A client asks for more scope on refresh. | The requested scope must be a subset of the original grant. |
| Repudiation | No record shows who rotated a token or why a family ended. | Heimdall writes an audit event for each rotation, reuse detection, and revocation. It includes the family ID and the correlation ID. |
| Information disclosure | An attacker reads tokens from the database. | Heimdall stores SHA-256 hashes only (D3). The plain token appears once, in the response (D6). |
| Denial of service | An attacker with a stolen token triggers reuse on purpose, so the victim loses the session. | Accepted. The victim signs in again. This failure is safer than leaving a live session to the thief. Alerts make the pattern visible. |
| Denial of service | A real client retries after it loses a response and triggers reuse detection. | Decision: no grace window. A grace window reopens the race that reuse detection closes. A client must save the new token before it uses it. The integration guide states this. |
| Denial of service | Expired tokens and families fill the database. | A scheduled job deletes expired families. Indexes exist on `TokenFamilyId` and `TokenHash`. |
| Elevation of privilege | A client rotates forever and keeps a session without end. | The family has an absolute lifetime (for example, 30 days) and an idle timeout. Rotation does not extend either one. A user or admin revocation ends the whole family. |
| Elevation of privilege | A refresh succeeds after the user account is disabled or consent is removed. | On each refresh, Heimdall checks that the user is active and consent exists. If not, it returns `invalid_grant` and revokes the family. The consent check comes with persisted consent (Phase 3). Until then, consent is a decision for one stored request. No stored consent exists that a user could remove. |

## `/.well-known/jwks.json`

Boundary: B5. The endpoint is public, unauthenticated, read-only, and has high request volume.

| STRIDE | Threat | Mitigation |
|---|---|---|
| Spoofing | An attacker serves a fake JWKS (DNS or man-in-the-middle). Forged tokens then pass checks. | TLS and HSTS (D1). Resource servers fetch keys only from the configured issuer. They take `jwks_uri` from discovery over TLS. They ignore `jku` and `x5u` headers in tokens. |
| Tampering | An attacker changes the key set that Heimdall serves. | Heimdall serves the set from memory, built from the key store. Only the key-management component can write to the key store (B4). On deployment, Key Vault or KMS holds the keys. |
| Tampering | The endpoint exposes private key material. | The response contains only public fields: `kty`, `n`, `e`, `kid`, `use`, `alg`. A separate public-key type makes it impossible to serialize private fields. |
| Repudiation | It is not clear which key signed a disputed token. | Each token header has a `kid`. Heimdall writes each key event to the audit log: created, activated, retired, removed. |
| Information disclosure | Retired-key data or key store details leak. | The JWKS lists only active keys and keys in the overlap period. It shows no internal identifier except `kid`. |
| Denial of service | Many requests hit the database for each call. | Heimdall caches the keys in memory and refreshes the cache on rotation. It sends `Cache-Control: public, max-age=...` and an `ETag`. A CDN or reverse proxy sits in front on deployment. An IP rate limit is the backstop. |
| Denial of service | All resource servers refetch the JWKS at the same time after a rotation. | `max-age` spreads the refetch times. Resource servers throttle refetches for an unknown `kid`. The documentation states this. |
| Elevation of privilege | An attacker steals a signing key and creates valid tokens. | Emergency procedure: an operator runs `remove-key <tenant host> <kid>`. The key leaves the JWKS at once. Tokens that this key signed stop working. This cost is accepted. Heimdall then activates a ready next key, or creates a new key. Token issuance stops until the new key is active, at most one publish wait. Key Vault or KMS keeps private keys non-exportable. Each server reloads its active key within the server key cache lifetime. Until then, another server can still sign with the removed key. Resource servers reject those tokens after their JWKS cache expires. |
| Elevation of privilege | Rotation breaks live tokens. Or a new key signs before caches know it. | Publish the new key in the JWKS at least one cache lifetime before it signs a token. The wait also covers the server key cache lifetime, because another server can serve the old JWKS for that long. Keep the old `kid` listed until its last token expires (token lifetime plus clock skew). |

## `POST /oauth/v1/revoke` (RFC 7009)

Boundary: B2. The endpoint revokes a refresh token with its family, or an access token.

| STRIDE | Threat | Mitigation |
|---|---|---|
| Spoofing | An attacker revokes the tokens of another client. | Confidential clients authenticate as at `/token` (D4, D5). The family's client must equal the caller. On a mismatch, Heimdall revokes nothing, returns `200`, and writes `revocation.refused`. |
| Spoofing | An attacker guesses client secrets at `/revoke`, because it is not `/token`. | Heimdall audits each failed client authentication at `/revoke` as `revocation.refused`, as it does at `/token`. |
| Spoofing | A public client revokes with a stolen token. | The refresh token is already a bearer secret. Whoever holds it can revoke it. Revocation only helps the real owner. |
| Tampering | A request repeats a parameter or sends credentials in the query string. | The same rules as `/token`: form body only, no repeated parameters. |
| Repudiation | A user or client disputes a revocation. | Heimdall writes `family.revoked` for each revoked family. The event has the family ID, the client, the caller IP, and the correlation ID. The family reason is `user_logout`. A request that revokes nothing goes to the log only. |
| Information disclosure | The response shows whether a token existed or was valid. | Heimdall returns `200` for an unknown, expired, revoked, or foreign token (RFC 7009, section 2.2). Only a malformed request or failed client authentication gets an error. |
| Denial of service | An attacker sends many revocations to flood or lock rows. | Rate limit for each IP and each `client_id`. Revocation is one indexed update on `TokenFamilyId`. |
| Elevation of privilege | A revoked refresh token family continues to work. | Heimdall revokes the whole family with one statement. This includes the newest refresh token. Any token of the family revokes it, also a used one. This is not reuse, because revocation only removes access. |
| Elevation of privilege | A revoked access token still works until it expires. | Accepted risk for offline validation. Access tokens are stateless JWTs with a lifetime of 5 minutes (D8). A resource server that needs immediate revocation uses introspection (D38). |

## `POST /oauth/v1/introspect` (RFC 7662, issue #19)

Status: decided by Claude on 2026-10-26, under the owner's go-ahead for the Phase 2 group. Built on 2026-10-26. The owner can review D36 to D39.

Boundary: B2. A resource server asks if a token is active now. Offline validation with the JWKS stays the normal path, because it needs no call. Introspection is for a resource server that must see a sign-out or a reuse before `exp`.

| ID | Decision | Reason |
|---|---|---|
| D36 | `POST /oauth/v1/introspect` takes the form rules of `/token` and `/revoke`. Only a confidential client can call it, with `client_secret_basic`. A public client gets `invalid_client`. | RFC 7662, section 2.1: the endpoint must be protected. A public client cannot keep a secret, so it cannot prove that it is a resource server. |
| D37 | A caller sees a token only when it may. An access token counts when its `aud` is one of the caller's `resource_audiences`, or its `client_id` is the caller. A refresh token counts only for the client of its family. Every other token gets `{"active": false}`, the same answer as an unknown token. | RFC 7662, section 4: the endpoint must not be an oracle for tokens of other clients. `resource_audiences` is a new registration list. It names the audiences that the client serves as a resource server (D22 names the audiences that a client may ask for). |
| D38 | An access token is active when its format, header, and signature are valid with the in-memory keys, `iss` is the tenant, `exp` is in the future, and its client is still active (the in-memory client cache). A token from a user grant also needs its family (`fid`, D29) to exist with no `revoked_at`, and its user to be active: one read joins both. A `client_credentials` token has no family, so it needs no read. A refresh token is active when it is unused, its family is unrevoked and inside both limits, and its user is active. | The family carries every revocation: a sign-out (D33), a reuse, and `/revoke`. So one read sees all of them. A disabled user or client gets nothing with a valid token, as at `/userinfo` and `/token`. A purged family is long past any access token, so a missing family means inactive. An automated security review on 2026-10-26 found the missing user and client checks. |
| D39 | An active answer has `active`, `scope`, `client_id`, `sub`, `aud`, `iss`, `exp`, `iat`, and `token_type` (`Bearer` or `DPoP`), and `cnf.jkt` for a bound token (RFC 9449, section 6.2). A refresh token answer has no `aud` and no `token_type`. Each answer has `Cache-Control: no-store`. Heimdall writes no audit event for a lookup, only for a failed client authentication (`introspection.refused`). | A resource server needs the claims to decide, and it must not keep an old answer. An audit row for each lookup would put a database write on a call that resource servers make often. |

| STRIDE | Threat | Mitigation |
|---|---|---|
| Spoofing | An attacker guesses client secrets at `/introspect`. | Heimdall audits each failed client authentication as `introspection.refused`. The per-IP failure limit of `/token` and `/revoke` applies (D36). |
| Spoofing | A public client, or a stolen `client_id`, asks about tokens. | Only a confidential client with its secret can call (D36). |
| Tampering | A request repeats a parameter or sends the token in the query string. | The form rules of `/token` apply. A query string is refused. |
| Repudiation | A resource server says that Heimdall called a revoked token active. | The family row keeps `revoked_at` and the reason, and the audit log has `family.revoked`. The answer depends only on that row and the token. |
| Information disclosure | A client learns the claims of another client's token, or learns that a stolen token is still valid. | A token that the caller may not see gets `{"active": false}`, the same as an unknown token (D37). |
| Information disclosure | A proxy or the resource server keeps an old answer. | `Cache-Control: no-store` on each answer (D39). |
| Denial of service | Many introspections load the database. | An access token costs one primary-key read, and a `client_credentials` token costs none. Client authentication reads the in-memory client cache. The per-IP failure limit applies. Resource servers should validate offline first. |
| Elevation of privilege | A token stays active after a sign-out or a reuse. | The family read sees every revocation at once (D38). |
| Elevation of privilege | A token of a disabled user or client stays active. | The same read checks the user's status, and the client cache checks the client's status (D38). |

## `POST /oauth/v1/par` (RFC 9126, issue #18)

Status: decided by Claude on 2026-10-28, under the owner's go-ahead for the Phase 2 group. Built on 2026-10-28. The owner can review D40 to D43.

Boundary: B2. The client sends its authorization parameters to Heimdall directly. The browser then carries only a reference, so nobody can read or change the parameters in the browser's address.

| ID | Decision | Reason |
|---|---|---|
| D40 | `POST /oauth/v1/par` takes the form rules of `/token`. A confidential client authenticates with `client_secret_basic`. A public client sends its `client_id` only. A DPoP proof is optional for every client. It binds the code to its key, as `dpop_jkt` does. With both, they must name the same key. | RFC 9126, section 2, and RFC 9449, section 10.1. For a public client, PAR does not prove who sent the request. It stops a change of the parameters on the way. |
| D41 | Heimdall runs every check of `/authorize` on the pushed parameters, with the same code. It stores the request in `authorization_requests` with the SHA-256 of a new `request_uri`: `urn:ietf:params:oauth:request_uri:` and 256 random bits. The request lives 60 seconds. A refused request gets a JSON error, never a redirect. | One check path means that a pushed request can never pass a rule that a browser request fails. Only the hash is stored (D3). The browser carries the `request_uri`, so its life must be short (RFC 9126, section 2.2). |
| D42 | `/authorize` with `request_uri` and `client_id` takes the request with one conditional statement. The statement matches only this client and an unexpired request. It clears the hash and gives the request the normal 10 minutes for the sign-in pages. Heimdall ignores every other parameter in the address. An unknown, used, expired, or foreign `request_uri` gets Heimdall's error page. | The conditional statement makes a `request_uri` single use, also under concurrent requests, as for codes. A `request_uri` sent with another `client_id` matches no row, so it cannot burn the real client's request. Heimdall cannot trust a redirect URI that it cannot find. |
| D43 | A client can require PAR (`require_pushed_authorization_requests`). `/authorize` then refuses its requests without `request_uri` with `invalid_request` to the redirect URI. Discovery says `require_pushed_authorization_requests: false` for the server. | RFC 9126, section 6. A client that never sends parameters in the address can make that a rule. The server does not require PAR from all clients, so existing clients keep working. |

| STRIDE | Threat | Mitigation |
|---|---|---|
| Spoofing | An attacker guesses client secrets at `/par`. | Heimdall audits each failed client authentication as `par.refused`. The per-IP failure limit of `/token` applies (D40). |
| Spoofing | An attacker uses a stolen `request_uri` with another client. | The take statement matches only the client of the request. The real client's request stays usable (D42). |
| Tampering | An attacker changes the scope or the redirect URI in the browser's address. | Heimdall uses only the pushed values and ignores the address (D42). |
| Tampering | A pushed request carries another `request_uri`. | Heimdall refuses it with `invalid_request` (D41). |
| Repudiation | A client says that it never pushed a request. | Only an authenticated or named client can push. The code that the request gives writes `code.issued` with the client. |
| Information disclosure | The authorization parameters leak through the browser history or a proxy log. | They never enter the address. The `request_uri` is opaque, lives 60 seconds, and works once (D41, D42). |
| Information disclosure | A database leak shows usable `request_uri` values. | Heimdall stores only their SHA-256 (D3). |
| Denial of service | A client fills `authorization_requests` with pushed rows. | Each push counts against the client's issuance limit. The purge job deletes expired rows. |
| Elevation of privilege | A pushed request passes a check that a browser request fails. | `/par` and `/authorize` share one check (D41). |
| Elevation of privilege | A `request_uri` works twice, so one request gives two codes. | One conditional statement clears the hash. A concurrent second use matches no row (D42). |

## Client authentication with `private_key_jwt` (RFC 7523, issue #67)

Status: decided on 2026-10-28. The owner chose the key source (D46), the `aud` rule (D48), and one method for each client (D47). Claude decided the other parts under the owner's go-ahead for Phase 2.

Boundary: B2. A confidential client proves who it is with a JWT that it signs with its private key. The same rules apply at `/token`, `/revoke`, `/introspect`, and `/par`.

| ID | Decision | Reason |
|---|---|---|
| D45 | A confidential client can authenticate with `private_key_jwt` (RFC 7523, section 2.2; OpenID Connect Core, section 9). The request sends `client_assertion_type` `urn:ietf:params:oauth:client-assertion-type:jwt-bearer` and `client_assertion`. A `client_id` in the body is optional and must name the same client. | The client keeps its private key. Heimdall stores only the public key, so a database leak, a log, or a proxy gives no credential that works. |
| D46 | The operator registers the client's public keys inline, as a JWK Set (`jwks`). Heimdall never fetches keys from a `jwks_uri`. Each key needs a unique `kid`, `kty` `RSA` or `EC`, and no private member. A set has 1 to 5 keys. A new set replaces the old one, for a rotation. | An inline set needs no outbound call on the request path and gives no server-side request forgery. A private member means a registration mistake that would put the client's secret into the database, so Heimdall refuses it. A `jwks_uri` can come in a later phase. |
| D47 | Each confidential client has exactly one method: `client_secret_basic` or `private_key_jwt`. A request with the other method gets `invalid_client`, also when its credential would be valid. A request with both a Basic header and an assertion gets `invalid_request` (RFC 6749, section 2.3). | The secrets of a client that moved to keys never work again, so a leaked old secret gives nothing. One method for each client also keeps the checks simple to test. |
| D48 | An assertion is valid when: `alg` is `RS256`, `PS256`, or `ES256` and matches the key type and the key's own `alg`; `kid` names a registered key; `crit` is absent; `typ`, when present, is `JWT` or `client-authentication+jwt`; `iss` and `sub` are the `client_id`; `aud` is exactly the tenant's issuer, as one string; `jti` is present; `exp` is in the future and at most 5 minutes away; `iat` and `nbf`, when present, are not in the future. A clock difference of 60 seconds is allowed. | The `aud` rule follows draft-ietf-oauth-rfc7523bis and the 2025 fix for the audience injection attack: an assertion made for another server, or for one endpoint URL, cannot work here. A `typ` for another JWT stops a DPoP proof or an access token from being used as an assertion. A short life limits a stolen assertion and keeps the replay table small. |
| D49 | Each assertion works once. One `INSERT ... ON CONFLICT DO NOTHING` into `client_assertions` records the SHA-256 of the client's primary key and the `jti`, until `exp` plus the clock difference. The purge job deletes the rows after that. | RFC 7523, section 3, item 7 allows a server to refuse a reused `jti`. One atomic statement means that two servers that see one assertion at the same time give one success, as for DPoP proofs (D26). |

| STRIDE | Threat | Mitigation |
|---|---|---|
| **Spoofing** | An attacker replays a captured assertion. | The `jti` works once for each client (D49). The assertion lives at most 5 minutes (D48). |
| Spoofing | An attacker uses an assertion that the client made for another server (audience injection). | `aud` must be exactly this tenant's issuer, as one string (D48). An endpoint URL or an array fails. |
| Spoofing | An attacker uses a DPoP proof, an access token, or an ID token as an assertion. | The `typ` check refuses other JWT types. `iss` and `sub` must be the `client_id`, and `aud` must be the issuer, which no other Heimdall token has (D48). |
| Spoofing | An attacker uses an old secret of a client that moved to keys. | One method for each client (D47). The secrets of a `private_key_jwt` client never work. |
| Tampering | An attacker changes the claims of an assertion. | Heimdall checks the signature with the registered key that `kid` names. The algorithm comes from Heimdall's list, never from the assertion alone (D48). |
| Information disclosure | The database leaks. | Heimdall stores only public keys for these clients. The replay table holds only hashes (D49). |
| Denial of service | An attacker sends many assertions to make Heimdall verify signatures. | The per-IP failure limit of `/token` applies before any database work. The size limit (4 KB) applies before any decoding. A check tries one key, the one that `kid` names. |
| Elevation of privilege | An operator registers a private key by mistake. | Heimdall refuses a key with a private member (D46). |

## `GET /oauth/v1/userinfo`

Boundary: B2 and B5. The endpoint needs an access token, as a bearer token or as a DPoP-bound token (D28). It returns the claims of the subject.

| ID | Decision | Reason |
|---|---|---|
| D44 | `/userinfo` reads the token's family (`fid`, D29) and its user in one query. The token is valid only when the family exists, has no `revoked_at`, belongs to the token's `sub`, and the user is active. A token without `fid` is invalid. | A sign-out (D33), a code or refresh token reuse, and `/revoke` all revoke the family. With this read, `/userinfo` refuses the family's access token at once, as introspection does (D38). The read replaces the user read, so `/userinfo` still opens one connection (#15). The conformance test `oidcc-codereuse-30seconds` found the gap. The owner chose this on 2026-10-28. |

| STRIDE | Threat | Mitigation |
|---|---|---|
| Spoofing | An attacker sends a forged token, or a token for a different issuer or audience. | Heimdall checks the signature with `RS256` only (D8), with the tenant's published keys from memory. The `typ` must be `at+jwt`, so an ID token fails. It checks `iss`, `exp`, and that `aud` is the userinfo endpoint (D22). It rejects `client_credentials` tokens, because their subject is not a user. |
| Spoofing | An attacker replays a stolen access token. | The short lifetime (D8). A DPoP-bound token works only with the `DPoP` scheme and a proof from its key, for this method, this URL, and this token (`ath`). Each proof works once (D26, D28). A bound token sent as `Bearer` gets `invalid_token`. |
| Spoofing | A client presents an unbound token with the `DPoP` scheme, to look bound. | Heimdall refuses an unbound token with the `DPoP` scheme (`invalid_token`). A `cnf` that Heimdall cannot read makes the token invalid, so a bound token never falls back to a bearer token. |
| Tampering | A client sends the token in the query string or form body. Logs and caches keep it. | Heimdall accepts the `Authorization` header only, with the `Bearer` or the `DPoP` scheme. A token in the query string gets `invalid_request`, so the client developer sees the mistake. |
| Repudiation | A party disputes access to user data. | Heimdall writes `userinfo.read` for each successful call: `sub`, `client_id`, released scopes, correlation ID. It does not log claim values. A refused call goes to the log only. |
| Information disclosure | The response gives more claims than the scope allows. | Heimdall releases only the claims that the granted scopes allow. Today `email` releases `email` and `email_verified`. `email_verified` is always false, because Heimdall has no email verification yet. The `sub` always equals the `sub` of the ID token. |
| Information disclosure | A browser or proxy caches the response. | `Cache-Control: no-store`. CORS allows only client origins of the tenant (D23). It never uses `*`. Each response has `Vary: Origin`. |
| Information disclosure | An error response shows details. | Heimdall returns a generic `invalid_token` error with no reason (D5). |
| Denial of service | A flood of calls causes one database read for each call. | Rate limit for each subject and each IP. Heimdall loads claims by primary key. A short-lived cache of user claims is optional. |
| Elevation of privilege | A disabled or deleted user, or removed consent, still gets data until the token expires. | Heimdall loads the user on each call. It rejects an inactive user. This check is stricter than a JWT check alone. The consent check comes with persisted consent (Phase 3). |
| Elevation of privilege | An attacker uses an access token after a code reuse, a sign-out, or `/revoke` ended its family. | Heimdall reads the family with the user on each call. A revoked or missing family makes the token invalid at once (D44). |
| Elevation of privilege | A token with only the `openid` scope reads profile claims. | Heimdall maps scopes to claims on the server. |

## Cross-origin reads (CORS)

Boundary: B1. A page on another origin calls `/token`, `/revoke`, or `/userinfo` in the user's browser. CORS decides only whether that page may read the response. Each endpoint still checks its code, verifier, token, or secret (D23).

| STRIDE | Threat | Mitigation |
|---|---|---|
| Spoofing | A malicious page sends a stolen code or refresh token from the user's browser and reads the new tokens. | Heimdall names only a client origin of the tenant in `Access-Control-Allow-Origin`. The browser blocks the read for any other origin. The code also needs the PKCE verifier, and the refresh token needs its family's `client_id`. |
| Spoofing | A page on a look-alike origin, such as `https://app.example.com.evil.example`, passes a prefix or suffix check. | Heimdall compares the whole origin by exact ordinal string. No prefix, suffix, or wildcard match exists. |
| Spoofing | A sandboxed iframe or a local file sends the origin `null`. | The value `null` never matches. A request with two `Origin` headers never matches. |
| Tampering | An attacker registers a client with an evil redirect URI to add a client origin. | Only an active client counts. A new client is `pending` until an admin approves it. A disabled client's origins stop working on the next cache load, or at once on this server after `Invalidate`. |
| Tampering | A confidential client's redirect URI adds an origin that does not need CORS. | Only public clients have client origins. A confidential client keeps its secret on a server, so its pages never call these endpoints. A loopback `http` redirect URI belongs to a native app and adds no origin. |
| Repudiation | It is unclear which origin read a token response. | Accepted. CORS is a browser control, and a non-browser caller can send any `Origin`. Heimdall audits the grant, not the origin. |
| Information disclosure | A cross-origin page reads the session API, such as `/session/v1/me`, with the user's cookie. | The session API sends no CORS header. Heimdall never sends `Access-Control-Allow-Credentials`, so a cross-origin request never carries the session cookie. |
| Information disclosure | A shared cache serves one origin's response, with its `Access-Control-Allow-Origin`, to another origin. | Each response of these three endpoints has `Vary: Origin`. The token and userinfo responses are also `no-store`. |
| Information disclosure | A wildcard on discovery or JWKS leaks private data. | Accepted on purpose. Both documents are public, have the same body for every caller, and carry no credentials. |
| Denial of service | A flood of preflight requests loads the database. | The check reads the tenant's client origins from the client cache in memory. A preflight runs before the rate limiter and uses no permit. |
| Elevation of privilege | A preflight lets a page send a header or method that the endpoint does not expect. | Each endpoint has a fixed rule. `/token` and `/revoke` allow `POST` with no extra header. `/userinfo` allows `GET` and `POST` with `Authorization`. Any other request gets a preflight answer with no CORS header. |

## User login, session, and consent pages

Boundary: B1. Heimdall shows these pages in the user's browser. `/authorize` sends the user here when no valid session exists, or when consent is missing.

Additional decisions for this boundary:

| ID | Decision | Reason |
|---|---|---|
| D11 | The session cookie uses the `__Host-` prefix and the flags `Secure`, `HttpOnly`, and `SameSite=Lax`. It has no `Domain` attribute. | `Lax` is required. A client sends the user to `/authorize` with a top-level cross-site navigation. `Strict` would drop the cookie, and the user would appear signed out. |
| D12 | The cookie holds the session list of the browser: one to five session IDs, joined by `.`. Each ID is 256 random bits and names one session of one user. The server stores each session and a hash of its ID. Heimdall refuses a malformed cookie value as a whole, before the database. | The browser holds no user data. The server can end a session at any time. One browser can hold several accounts (#41). Base64url text has no `.`, so the split is exact. |
| D13 | Heimdall issues a new session ID at each sign-in. It never adopts a session ID from the request. When the user already has a live session in the list, that session continues: it gets the new ID, a new `auth_time`, and a new absolute lifetime, and it keeps its `sid`. The old ID stops working in the same statement. Sessions of other users stay in the list. | This stops session fixation. The same `sid` keeps the token families of the session linked to a session that a sign-out can end (D33). |
| D14 | A password has at least 12 characters and at most 128. Heimdall rejects passwords from a breached-password list. It has no composition rules. | This follows NIST SP 800-63B. Length and the breach check protect users better than character rules. |
| D50 | A session list holds at most five sessions. This rule has no setting. A sign-in to a full list first drops the ended sessions, oldest entry first. If five live sessions remain, Heimdall refuses the sign-in with `session_limit`, after it checks the password. | The cap limits the cookie size and the query for each request. Heimdall never ends a live session without the user's request. The refusal comes after the password check, so it shows nothing about an account to a caller who does not know the password. |

| STRIDE | Threat | Mitigation |
|---|---|---|
| **Spoofing** | Credential stuffing: an attacker tries leaked passwords from other sites. | Heimdall limits sign-in attempts for each IP. It throttles failures for each account and source: after 5 failures, the wait doubles with each failure, up to 15 minutes. During a wait, Heimdall does not check the password, so guessing makes no progress. The attempt costs one dummy hash and gets the generic failure, so a throttled account looks like any failed sign-in. It does not lock the account (see denial of service). It checks passwords against a breached-password list (D14). Multi-factor authentication with WebAuthn comes in Phase 3. |
| Spoofing | An attacker learns which accounts exist from the login error or the response time. | Heimdall returns one generic error for an unknown user and a wrong password. For an unknown user, it still computes an Argon2id hash against a dummy value, so the response time is the same. |
| Spoofing | Session fixation: an attacker sets a known session ID before sign-in. | Heimdall issues a new session ID at each sign-in and adopts none from the request (D13). It never accepts a session ID from the URL. |
| Spoofing | An attacker adds a session of the attacker's own account to the victim's session list. The victim then works in the attacker's account. | Only the tenant origin can set a `__Host-` cookie, over TLS (D11). The risk that remains needs script execution on the tenant origin. The account picker (#41) shows the email of each account. |
| Denial of service | A cookie with many session IDs causes a large query. | Heimdall refuses a value with more than five IDs before the database (D12, D50). |
| Spoofing | An attacker steals the session cookie. | `HttpOnly` blocks script access. `Secure` and HSTS (D1) block network capture. The session has an idle timeout and an absolute lifetime. |
| Spoofing | Login CSRF: an attacker signs the victim in to the attacker's account. | The login form has an anti-forgery token. `SameSite=Lax` also applies (D11). |
| Spoofing | CSRF on the JSON login API that the Angular page calls (`/session/v1/login` and `/logout`). | Three layers. The page sends the antiforgery token from the `__Host-XSRF-TOKEN` cookie in the `X-XSRF-TOKEN` header (double-submit). The API accepts only JSON, and a cross-site script needs a CORS preflight for JSON, which Heimdall never allows. A browser `Origin` header must equal the tenant origin. |
| Information disclosure | A cross-origin script reads a session API response, such as `/session/v1/me`. | Heimdall sends no CORS headers, so the browser blocks the read. The responses are `no-store`. |
| **Tampering** | CSRF on the consent form: an attacker's page submits consent for the victim. | The consent API (`POST /session/v1/consent`) has the same three CSRF layers as the login API. Heimdall links the decision to the pending authorization request stored on the server. The browser cannot change the client or the scope. |
| Spoofing | A second user signs in on the same browser and uses the first user's consent decision. | The stored request records the user who decided. A decision counts only for that user. |
| Elevation of privilege | A user denies consent, and a script then approves the same request. | A denial ends the stored request at the resume step. A later decision or resume finds no request. |
| Elevation of privilege | A client that requires consent sends a `prompt` value to skip the consent page. | Heimdall shows the consent page when the client requires consent or the request has `prompt=consent`. No `prompt` value removes the page. `prompt=none` with consent required gets `consent_required`. |
| Spoofing | A script decides consent for a pushed request before `/authorize` takes its `request_uri`. | The consent API refuses a stored request that still has a `request_uri` hash. That request has no consent page yet (D42). |
| Tampering | A user or script changes the client or scope in the consent form. | Heimdall reads the client and scope from the stored request. The API accepts only the request ID and the decision. |
| Tampering | Open redirect: the post-login return URL sends the user to an attacker's site. | Heimdall returns only to a stored `/authorize` request. It accepts no free-form return URL. |
| Tampering | Clickjacking: an attacker frames the login or consent page and tricks the user into a click. | Heimdall sends `Content-Security-Policy: frame-ancestors 'none'` and `X-Frame-Options: DENY` on these pages. |
| **Repudiation** | A user says they did not sign in, or did not log out. | Heimdall writes an audit event for each sign-in, failure, consent, and logout. The event has the session ID hash, IP, user agent, and correlation ID. |
| **Information disclosure** | The password, session ID, or CSRF token appears in logs or URLs. | D7. Heimdall sends the password only in a POST body over TLS. The session ID is only in the cookie. |
| Information disclosure | Cross-site scripting (XSS) on a Heimdall page reads page data or acts as the user. | Heimdall encodes all output. It sends a strict `Content-Security-Policy`. It uses no inline script. XSS can read the antiforgery request token, which that pattern accepts. XSS cannot read the session cookie, because it is `HttpOnly`. |
| Tampering | A compromised npm package in the Angular build runs in the login page (supply chain). | Open: decide with the Angular work. Options are a lockfile with integrity hashes, a dependency review in CI, and a strict CSP with no third-party script origins. |
| Information disclosure | The OpenAPI document or its Scalar page describes the session API to an attacker, or the page loads script from a third party. | Heimdall maps `/openapi/v1.json` and `/scalar/` in Development only (#22). The page has its own policy: script and style from Heimdall and inline only, `connect-src 'self'`, and `frame-ancestors 'none'`. Scalar's fonts are off. |
| Information disclosure | The consent page shows client data that an attacker controls, such as the client name. | Heimdall encodes the name. An admin approves the client registration (see `/authorize`). Heimdall shows the registered redirect URI host. |
| **Denial of service** | An attacker sends failed logins on purpose to lock out a victim. | Heimdall throttles. It does not lock. The throttle is for each account and source, so the attacker's failures slow only the attacker's source. The real user at another address can still sign in. A distributed attacker with many addresses gets a separate wait at each one, and the IP rate limit still applies to each. |
| Denial of service | Argon2id costs much CPU and memory. An attacker sends many login requests. | Rate limit for each IP before the hash runs. A limit on the number of concurrent hash operations. |
| **Elevation of privilege** | A session stays valid after a password change or account disable. | Heimdall ends all sessions of the user on password change and on disable. It checks the user status on each `/authorize` request. |
| Elevation of privilege | Logout CSRF: an attacker's page ends the victim's session. | Logout needs a POST with an anti-forgery token. RP-initiated logout ends a session without a click only with a valid ID token of this session (D31). |
| Elevation of privilege | A session never ends. | The session has an idle timeout and an absolute lifetime. Neither one extends the other. |

Out of scope for now: registration, email verification, password reset, and account recovery. Each one needs its own table. They are the most common route to account takeover, so add them before any public deployment.

## Tenants and client configuration

Boundaries: B2 and B3. Heimdall is multi-tenant. The schema has a `Tenant` table from the first migration. Tenant administration features (portal, onboarding) arrive in Phase 3.

Decisions for this area:

| ID | Decision | Reason |
|---|---|---|
| D15 | Settings have three layers: platform defaults, tenant settings, and client settings. The most specific layer wins. Each layer must stay inside the limits of the layer above. | A tenant or client cannot weaken a platform rule. |
| D16 | The platform sets a minimum and a maximum for each setting. Heimdall rejects a value outside the range when the admin saves it. | Misconfiguration cannot create an insecure policy. |
| D17 | These rules have no setting: PKCE with `S256`, `RS256` only, exact-match redirect URIs, family revocation on reuse, no grace window, and hashing at rest. | The weakest client must not set the security of all clients. |
| D18 | The login session lifetime is a tenant setting. A client cannot lengthen it. A client can make it shorter with `max_age`. | The session cookie is shared by all clients of a tenant (single sign-on). |
| D19 | Each tenant has its own issuer URL, user pool, clients, and signing keys. Each token carries the tenant's `iss`. | A token from tenant A must not be valid in tenant B. |
| D20 | Every tenant-owned table has a `TenantId` column. Each unique index includes `TenantId`. EF Core global query filters apply `TenantId` to every query. PostgreSQL row-level security is a second layer. | One missed filter must not expose another tenant's data. |
| D21 | Heimdall finds the tenant from the host name (one subdomain for each tenant). | Each tenant gets its own browser origin and its own `__Host-` cookie. Path-based tenants would share one cookie. |

| STRIDE | Threat | Mitigation |
|---|---|---|
| **Spoofing** | A token from tenant A is accepted by a resource server or endpoint of tenant B. | Each tenant has its own `iss` and signing keys (D19). Resource servers check `iss` and `aud`. `/userinfo` checks that the token's tenant equals the request's tenant. |
| Spoofing | A user of tenant A signs in with a session from tenant B. | The server-side session stores `TenantId`. Heimdall rejects a session whose tenant differs from the request's tenant. |
| **Tampering** | A client admin sets a policy outside the limits, such as a very long token lifetime. | Heimdall validates each value against the limits on save (D16). The database has check constraints for the same ranges. |
| Tampering | An attacker adds a redirect URI to a client. | A change to redirect URIs needs approval from a tenant admin or a platform admin. Heimdall writes an audit event. |
| **Repudiation** | A configuration change has no record. | Heimdall writes an audit event for each change, with the old value, the new value, the admin, and the tenant. |
| **Information disclosure** | A query without a tenant filter returns data of another tenant (insecure direct object reference). | D20. The EF Core filter is the first layer. PostgreSQL row-level security is the second layer: it also covers raw SQL. The application login is not a superuser, so the policies apply to it. Tests create two tenants and check that each endpoint refuses cross-tenant IDs. Other tests bypass the EF Core filter and check that PostgreSQL still refuses. |
| Information disclosure | An attacker learns which tenants exist from error messages or response time. | Heimdall returns the same response for an unknown tenant host and for a host with no content. |
| Spoofing | A client sends `X-Forwarded-For` or `X-Forwarded-Proto` to fake its address in the audit log or to pass the HTTPS check over plain HTTP. | Heimdall reads these headers only from the proxies in `Heimdall:ForwardedHeaders`. With none configured, it reads no forwarded header. It reads one hop only: the rightmost value, which the trusted proxy wrote. |
| Spoofing | A client sends `X-Forwarded-Host` to choose another tenant or issuer. | Heimdall never reads `X-Forwarded-Host`. The proxy must pass the original Host header (D21). |
| **Denial of service** | One tenant uses all capacity (noisy neighbor). | Rate limits apply for each tenant, each client, each IP, and each account. |
| **Elevation of privilege** | A tenant admin changes platform settings or another tenant. | Admin roles are separate: platform admin and tenant admin. Each admin API call checks the role and the `TenantId`. |
| Elevation of privilege | An admin disables a client or revokes a secret, but other servers still accept it. | Each server keeps a tenant's clients in memory for the server cache lifetime (1 minute). The server that makes the change drops its entry at once. This delay is accepted. Secret expiry has no delay: Heimdall checks it at each request. |
| Elevation of privilege | A client loosens a rule that has no setting (D17) by a hidden field. | Heimdall binds only known fields. The code has no setting for D17 rules. |

## Health endpoints

Boundary: the orchestrator inside the deployment. `/health/live` and `/health/ready` run before tenant resolution and before the HTTPS check, because a probe calls the container IP over plain HTTP.

| STRIDE | Threat | Mitigation |
|---|---|---|
| Information disclosure | A caller learns internal state, such as database errors, from a health response. | The body is one word: `Healthy` or `Unhealthy`. The reason stays on the server. |
| Information disclosure | The health endpoints are reachable from the internet over plain HTTP. | Set `Heimdall:Health:Port` to a management port. The endpoints then answer only on that port. Do not publish the port. |
| Denial of service | A database outage makes the orchestrator restart every server at once. | Liveness checks no dependency. Only readiness checks the database, so the orchestrator stops traffic but does not restart. |

## Telemetry

Boundary: the telemetry backend. OpenTelemetry sends traces and metrics over OTLP, only when `OTEL_EXPORTER_OTLP_ENDPOINT` is set. D7 applies to telemetry as it applies to logs.

| STRIDE | Threat | Mitigation |
|---|---|---|
| Information disclosure | A trace holds a `state`, a code challenge, or a token from a query string. | Heimdall removes the `url.query` tag from every server span. No setting of the instrumentation can turn this off. A test checks it. |
| Information disclosure | A trace holds the `Authorization` header or a cookie. | The instrumentation records no request headers. A test sends a bearer token and checks that no span holds it. |
| Information disclosure | A trace holds parameter values of SQL statements. | Npgsql records the SQL text only. Every value in Heimdall's SQL is a parameter. |
| Denial of service | A caller sends many different `grant_type` values and creates unbounded metric tag values. | Every tag value comes from a fixed set. An unknown grant type is counted as `other`. No tag holds a client ID or a user. |

## Limits and lifetimes

These values are the platform defaults. A tenant or client can change a value only inside the limits (D15, D16). Change a default only with a recorded reason. Store each value in configuration, not in code.

Platform limits (D16). A tenant or client value must be inside these ranges. The values are in configuration (`Heimdall:PlatformLimits`). They are proposed starting values, not final. The server does not start if a minimum is zero or greater than its maximum.

| Setting | Minimum | Maximum |
|---|---|---|
| Session idle timeout | 5 minutes | 24 hours |
| Session absolute lifetime | 1 hour | 30 days |
| Access token lifetime | 1 minute | 60 minutes |
| Refresh idle timeout | 1 hour | 30 days |
| Refresh absolute lifetime | 1 day | 90 days |

| Item | Value | Note |
|---|---|---|
| Code lifetime | 5 minutes | Single-use. |
| Access token lifetime | 5 minutes | D8. |
| Refresh token family, absolute lifetime | 30 days | Rotation does not extend it. |
| Refresh token family, idle timeout | 7 days | Rotation does not extend it beyond the absolute lifetime. |
| Login session, idle timeout | 30 minutes | |
| Login session, absolute lifetime | 12 hours | |
| JWKS cache lifetime (`max-age`) | 10 minutes | Configuration: `Heimdall:SigningKeys:JwksCacheLifetime`. Discovery uses the same `max-age`. |
| Server key cache lifetime | 1 minute | A key, tenant, or client change on one server reaches every other server within this time. The changing server applies it at once. |
| Publish wait | 11 minutes | A new key waits the JWKS cache lifetime plus the server key cache lifetime before it signs. |
| Key rotation interval | 90 days | The job creates the next key one publish wait before this time ends. Configuration: `Heimdall:SigningKeys:RotationInterval`. |
| Clock skew | 5 minutes | Resource servers allow this difference when they check `exp`. |
| Argon2id parameters | 64 MiB, 3 passes, 1 lane | Above the OWASP minimum (19 MiB, 2 passes). A sign-in upgrades an older hash. Configuration: `Heimdall:PasswordHashing`. |
| Concurrent password hashes | One for each CPU core | Requests wait up to 5 seconds for a slot, then fail fast. |
| Retired key overlap | 65 minutes | A retired key stays in the JWKS for the platform maximum access token lifetime (60 minutes) plus clock skew. |
| Purge job interval | 1 hour | Configuration: `Heimdall:Purge`. Also the batch size (1000) and the retentions below. |
| Retention of an ended family | 7 days | A reused token of a recent family still causes a revocation and an alert. |
| Retention of an expired code with no family | 24 hours | A replayed code still shows as redeemed. |
| Retention of an ended session | 7 days | For an investigation. |
| Rate limit, `/token` and `/revoke` failures | 60 each minute for each IP | Only failed requests count. An IP that reaches the limit gets 429 before any database work, also with the right secret. A backend's normal traffic from one IP never reaches it. |
| Rate limit, `/token` issuance | 300 each minute for each authenticated client | Only the client's own successful issuances count. A caller with a wrong secret cannot use up another client's budget. |
| Rate limit, login | 5 attempts each minute for each IP | Each attempt costs one Argon2id hash, so successes count too. The sign-in throttle for each account is a separate control. |
| Sign-in throttle for each account and source | 5 free failures, then 1 s doubling to 15 minutes | Configuration: `Heimdall:LoginThrottle`. A source with no failure for 24 hours starts again at zero. |
| Rate limit, `/authorize` | 120 requests each minute for each IP | Each request can store an authorization request. |

Decision (2026-10-19): the counters are in memory on each server. With N servers, a caller gets up to N times each limit. This still caps the CPU and database load of each server, which is the purpose. An IPv6 address counts as its /64 network. A refused request gets 429, `Retry-After`, and the error `temporarily_unavailable`. The values are in configuration (`Heimdall:RateLimits`). A shared IP address (for example, an office) can reach the login limit. Review the values with k6 results in Phase 4.

## Open items

- Choose the breached-password list for D14: a local list or the Have I Been Pwned range API (k-anonymity). Build it with registration and password change.
- Add tables for registration, email verification, password reset, and account recovery.
