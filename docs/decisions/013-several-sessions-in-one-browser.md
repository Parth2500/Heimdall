# DR-013: One browser holds several sessions (#41)

- Date: 2026-11-12
- Status: Accepted. Decided by the owner, from the options in the [account picker design note](../account-picker-design.md).
- Affects: D12 (changed), D13 (changed), D50 (new).

## Before

D12 said that the cookie holds one session ID. D13 said that Heimdall issues a new session ID at sign-in. The code also revoked the browser's old session at each sign-in. It did not revoke the token families of that session.

## After

The cookie holds a session list: one to five session IDs, joined by `.` (D12, D50). Each sign-in still gets a new session ID, and Heimdall adopts none from the request. A second sign-in of the same user continues the live session with the new ID and the same `sid`. Sessions of other users stay in the list (D13).

## Reason

The account picker (#41) needs several accounts in one browser. A list of session IDs in one cookie keeps D12 true for each session and needs no new table. A browser secret with a list on the server was not chosen: its fixation defense depends on one rotation, and it would end every current session.

The old code left token families without a live session after a second sign-in. A later sign-out could not find them, so D33 did not hold for them. The same `sid` closes that gap.

## Consequences

A stolen cookie value gives every account of the browser. An ID token from before a second sign-in still names the current session, so it can end that session without a click (D31). The sixth account in one browser gets `session_limit`. The later steps of #41 change D31, D33, U14, and U17. Each change gets its own record.
