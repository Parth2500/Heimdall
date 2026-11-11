# Account Picker: Design Note (#41)

Status: **Approved** by the owner on 2026-11-12, with one change: P10 keeps every ended account, as Entra does. The build is in progress (section 8). Each build step moves its decisions into the tables of the [threat model](threat-model.md) and the [front-end design](frontend-design.md).

This note changes recorded decisions (D12, D13, D31, U14, U17). The build commit writes DR-013.

## 1. Goal

A user can sign in to several accounts of one tenant in one browser. A client can ask for the account picker with `prompt=select_account`. The model is Microsoft Entra ID ("Pick an account").

## 2. What exists today

- The cookie `__Host-Heimdall.Session` holds one session ID (D11, D12). One browser holds one user.
- A sign-in revokes the browser's old session row and issues a new session ID (D13).
- `/authorize` accepts `prompt` values `none`, `login`, and `consent`. It refuses `select_account` with `invalid_request`.
- `max_age` and the `auth_time` claim are complete. This work does not change them.
- Heimdall ignores `login_hint`. It reads `id_token_hint` only at `/oauth/v1/logout`.
- The login page shows the email field and the password field together. The U16 mockups show two steps.

**A defect in the current code.** `SessionService.SignInAsync` revokes the old session row, but it does not revoke the token families of that session. D33 does not run. After a second sign-in, those families have a `sid` that no live session has. A later sign-out cannot find them. P4 below removes the defect.

## 3. Terms

These terms go into the glossary when the owner approves the note.

| Term | Meaning |
|---|---|
| Session | One sign-in of one user in one browser. It has one cookie secret and one `sid`. This meaning does not change. |
| Session list | The sessions that one browser's cookie names. |
| Live session | A session that passes every rule of `Session.IsValid`. |
| Ended session | A session in the session list that is not live. |
| Account picker | The Heimdall page that shows the session list and lets the user choose one account. |
| Selection | The user's choice of one session for one stored authorization request. |

## 4. Session model: three options

| | Option 1: one cookie, a list of session IDs | Option 2: one cookie for each account | Option 3: one browser secret, the list on the server |
|---|---|---|---|
| Cookie | `__Host-Heimdall.Session` holds up to five session IDs, joined by `.`. | Five cookies, one session ID each. | One secret that names a new `browsers` row. Sessions point to the row. |
| Schema change | None for sessions. | None for sessions. | New table. `sessions.id_hash` loses its purpose. |
| D12 (hash only on the server) | Holds for each session. | Holds for each session. | Changes. The cookie no longer holds a session ID. |
| D13 (session fixation) | Holds with no new rule. A sign-in always creates a new session ID. | The same. | Holds only if the server rotates the browser secret at each sign-in. A missed rotation gives the attacker the victim's sessions. |
| Limit | The server parses at most five IDs before the database. | The server must list cookies by name. | The server counts rows. |
| Cost at `/authorize` | One query: `id_hash = ANY(...)`, joined to `users`. | The same. | One query, with one more join. |
| A stolen cookie value | Gives all accounts of the browser. | Gives one account, but the cookies travel together. | Gives all accounts of the browser. |
| Current sessions at release | Stay valid. A cookie with one ID is a valid list. | Need a cookie rename. | All users sign in again, or the server keeps two code paths. |

**Recommendation: Option 1.** It keeps D12 and D13 true for each session, and it needs no new table. Option 2 adds cookie handling and gives no security gain, because the browser sends all the cookies together. Option 3 moves the trust to a new secret, and its fixation defense depends on one rotation that a later change can break.

Limit of the cookie, stated plainly: it has no `Expires` attribute, so the session list ends when the browser closes. The "Signed out" rows (P10) go with it. A list that survives a browser restart needs the "stay signed in" setting of the mockups, which is later work.

Limit of Option 1, stated plainly: a thief with the cookie value gets every account in the browser. Option 3 has the same limit. The defenses are the ones of D11: `HttpOnly`, `Secure`, the `__Host-` prefix, and the two timeouts.

## 5. Proposed decisions

The numbers P1 to P10 are for this note. An approved decision gets the next D or U number.

| ID | Decision | Reason |
|---|---|---|
| P1 | The session cookie holds a session list: one to five session IDs, joined by `.`. Each ID is 256 random bits, and the server stores only its hash (D12 for each session). Heimdall refuses a malformed value, or a value with more than five IDs, before the database. | Base64url text has no `.`, so the split is exact. Five IDs are 219 characters. The cap stops a large cookie from causing a large query. |
| P2 | The limit of five sessions is a platform rule with no setting. When the list is full, a new sign-in first drops the ended sessions. If five live sessions remain, the page tells the user to sign out of one account. | A fixed limit needs no new rows in the settings policy (D16). Heimdall never ends a live session without the user's request. |
| P3 | A sign-in adds one new session, with a new session ID and a new `sid`. Sessions of other users in the list stay. | This is the purpose of #41. A planted session ID never becomes the victim's session, because Heimdall never reuses an ID from the request (D13). |
| P4 | When the user who signs in already has a live session in the list, Heimdall re-authenticates that session. It replaces the cookie secret, sets `AuthTime`, and starts a new absolute lifetime. The `sid` stays the same. | The clients of that session keep one `sid`. Their token families stay linked to a live session, so a later sign-out revokes them (D33). This removes the defect in section 2. The new secret keeps the fixation defense. |
| P5 | `/authorize` chooses the session in this order. (1) A selection for this request, if that session is still live and in the list. (2) `id_token_hint`: the live session of the hint's `sub`. (3) `login_hint`: the live session whose user has that email. (4) No hint: with one live session, that session; with several, the account picker. | A user's explicit choice wins over a client's hint. One live session keeps single sign-on as it is today. With several, Heimdall must not guess, because a wrong guess signs the user in to a client as the wrong account. |
| P6 | `prompt=select_account` always shows the account picker, also with one live session. Only a selection made after the request was created satisfies it. With no session in the list, Heimdall shows the sign-in page. `prompt=none` with `select_account` is `invalid_request`. | OpenID Connect Core, section 3.1.2.1. The time rule is the same rule as `prompt=login`. |
| P7 | With `prompt=none`, Heimdall never shows the picker. Several live sessions and no usable hint give the error `account_selection_required`. A hint that names no live session gives `login_required`. | OpenID Connect Core, section 3.1.2.6, defines both codes. A client that renews without a page sends `id_token_hint` or `login_hint`, as MSAL does. |
| P8 | `login_hint` is an email address of at most 254 characters. Heimdall ignores any other value. The sign-in page fills the email field with it. Heimdall never answers whether the account exists. | The hint only saves typing. An answer about the account would be an enumeration oracle (D5). |
| P9 | A selection is one stored value on the authorization request: the `sid` and the time. The picker sends `POST /session/v1/select` with the three CSRF layers of the login API. A sign-in for a stored request records the selection in the same transaction. The resume step checks again that the selected session is live and in the cookie. | The choice binds to one request, like a consent decision. The second check stops a selection of a session that this browser does not hold. Here the `sid` only selects inside a list that the cookie already authenticated (D29 holds). |
| P10 | An ended session stays in the list as "Signed out", with its email, also after a user sign-out. A click on it opens the password step for that email. The row has a "Forget" action, which removes the ID from the cookie. The row also goes when the purge job deletes the session (7 days after its end). An ended session ID in the cookie authenticates nothing. | The owner chose the Entra behavior: the user signs in again without typing the email. The row is visible only to a holder of the `HttpOnly` cookie on the tenant origin. "Forget" is the control for a shared computer. |

### Sign-out with several accounts (changes D31 and U17)

| Case | Result |
|---|---|
| The `id_token_hint` is valid, and its `sid` is the `sid` of a live session in the list. | Heimdall ends that one session at once (D33). The other sessions stay. |
| Any other request, and the list has one live session. | The confirm page, as today. |
| Any other request, and the list has several live sessions. | The confirm page lists the accounts. The user ends one account or all accounts. A valid hint's `sub` marks its account first. |
| The list has no live session. | Nothing to end. Heimdall goes to the redirect step (D32). |

- "Sign out of all" ends every live session of the list in one transaction. D33 runs for each session.
- A sign-out no longer deletes the cookie (this changes the last step of D33). The ended ID stays for the "Signed out" row (P10).
- Back-channel logout does not change. It works for each `sid` (D34).
- `POST /session/v1/logout` gets a body field that names one `sid` of the list, or all sessions.
- A password change or a disabled account still ends the sessions of that user only.

### Session API changes

| Endpoint | Change |
|---|---|
| `GET /session/v1/accounts` | New. Returns the session list: display name, email, `sid`, and the state (signed in or signed out). `no-store`, no CORS header. |
| `POST /session/v1/select` | New. Records a selection for a stored request (P9). |
| `POST /session/v1/login` | Takes an optional request ID, and records the selection (P9). Applies P2 to P4. |
| `POST /session/v1/logout` | Names one session or all sessions. |
| `GET /session/v1/me` | Takes a request ID and returns the selected account. Without one, it answers only when the list has one live session. |

The idle timeout moves only for the session that `/authorize` uses. A view of the picker does not count as activity.

### Pages (U16 design, proposed as U18)

- **Account picker** (`Card-Picker` mockup): the list, "Use another account", and "Sign out of all".
- **Sign-in in two steps** (`Card-Email`, `Card-Password`): the email step, then the password step. The page sends one `POST` after the password step. The email step calls no server endpoint, because an answer at that step would show whether the account exists.
- **Sign in again** (`Edge-Reauth`): the password step with a fixed email, for `prompt=login`, `max_age`, and a "Signed out" row.
- **Sign-out confirm page**: gets the account choice.

## 6. Threats (STRIDE), new or changed

| STRIDE | Threat | Mitigation |
|---|---|---|
| Spoofing | Session fixation: an attacker plants a session ID before the victim signs in. | Heimdall creates a new session ID at each sign-in and never adopts one from the request (P3, P4). |
| Spoofing | An attacker plants a session of the attacker's own account into the victim's list. The victim then picks it and works in the attacker's account. | Only the tenant origin can set a `__Host-` cookie, over TLS. The picker shows the email of each account. The risk that remains needs script execution on the tenant origin. |
| Tampering | CSRF on the selection: an attacker's page chooses the account for the victim. | `POST /session/v1/select` has the three CSRF layers. The selection binds to one stored request (P9). |
| Tampering | A request names a `sid` that this browser does not hold. | The resume step accepts only a live session of the cookie's list (P9). |
| Repudiation | A user says they did not choose that account. | Heimdall writes an audit event for each selection, with the session hash and the correlation ID. |
| Information disclosure | Another site reads the account list. | The API sends no CORS header and `no-store`. The cookie is `HttpOnly`. The pages send `frame-ancestors 'none'`. |
| Information disclosure | A client learns that the browser holds several accounts, from `account_selection_required`. | Accepted. The error is one bit, and it goes only to a registered redirect URI. OpenID Connect defines the error for this case. |
| Information disclosure | A client uses `login_hint` to test whether an account exists. | The page looks the same for every hint. Heimdall gives no answer about the account (P8). |
| Information disclosure | A "Signed out" row shows an email on a shared computer. | Accepted by the owner. The row has a "Forget" action, and it goes after at most 7 days (P10). The signed-out page names the action. |
| Denial of service | A cookie with many IDs causes a large query. | Heimdall refuses more than five IDs before the database (P1). |
| Elevation of privilege | Consent from account A lets account B get a code. | A consent decision is for one request and one user. This rule exists today. |
| Elevation of privilege | A token family outlives its session after a second sign-in. | P4 keeps the `sid`, so D33 finds the family. |

## 7. Comparison with Microsoft Entra ID

- Entra shows the picker when the browser holds several accounts and the client sends no hint. P5 does the same.
- Entra accepts `login_hint` and a session hint to skip the picker. P5 uses `login_hint` and the standard `id_token_hint`.
- Entra keeps signed-out accounts in the list with a "Forget" action. P10 does the same, for at most 7 days.
- Entra has no fixed public limit. P2 sets five.

## 8. Build steps after approval

Each step has its tests and one commit.

Step 3 is done (2026-11-12): D31 and D33 changed, D55, DR-014. `/session/v1/me` did not change: no page uses it for a request. Two rules are sharper than P5: an ended session is never a candidate, so one live session beside signed-out rows serves the request; and an `id_token_hint` also limits a selection on the picker.

Step 2 is done (2026-11-12): D51 to D54 in the threat model. One rule is new against P5: a sign-in after the request was created counts as the user's choice, when it is the only one. Without it, `prompt=login` and "Use another account" would need the login API to record a selection. P9 no longer needs that, so the login API does not change.

Step 1 is done (2026-11-12): D12, D13, and D50 in the threat model, and DR-013. Until step 2, `/authorize`, the consent API, and sign-out use the live session of the latest sign-in. Until step 3, a sign-out ends every live session of the list and deletes the cookie, so no session stays live behind a deleted cookie.

1. **Session list.** Cookie parser, validation of the list in one query, the limit, and re-authentication in place (P1 to P4). `Session` gets the re-authentication rule.
2. **`/authorize`.** The session choice, `select_account`, `login_hint`, `id_token_hint`, and `account_selection_required` (P5 to P8). One migration adds the selection and the hint to `authorization_requests`.
3. **Session API and sign-out.** `/accounts`, `/select`, sign-out of one or all sessions, and the `/oauth/v1/logout` rule for a list (P9, P10).
4. **Pages.** The picker, the two-step sign-in, "sign in again", and the sign-out choice. WCAG 2.2 AA checks (U12).
5. **Documents and clients.** Threat model, DR-013, domain model, diagrams 06 and 07, the client guide, `CHANGELOG.md`, a conformance run, and a "switch account" action in the demo SPA.

## 9. The owner's answers (2026-11-12)

| Question | Answer |
|---|---|
| Session model | Option 1: one cookie with a list of session IDs. |
| Several live sessions and no hint (P5) | Heimdall shows the account picker. |
| Signed-out rows (P10) | Heimdall keeps every ended account, as Entra does. This replaced Claude's proposal to forget an account at sign-out. |
| Re-authentication (P4) | In place. The `sid` stays. |
| Limit (P2) | Five. The owner did not change the proposal. |
