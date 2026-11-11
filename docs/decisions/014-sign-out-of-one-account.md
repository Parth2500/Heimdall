# DR-014: A sign-out ends one account and keeps the cookie (#41)

- Date: 2026-11-12
- Status: Accepted. Decided by the owner, from the options in the [account picker design note](../account-picker-design.md).
- Affects: D31 (changed), D33 (changed), D55 (new).

## Before

D31 said that a valid hint ends "the browser's session", and that the confirm page ends it. D33 said that Heimdall deletes the session cookie after the transaction. One browser held one session.

## After

A valid hint ends only the session that its `sid` and `sub` name, when that session is live in the browser's session list. The confirm page ends one account, named by its `sid`, or every account (D31). The session cookie stays after a sign-out (D33). The account picker shows an ended session as "Signed out" until the user forgets it (D55).

## Reason

One browser now holds several accounts (DR-013). The client of one account must not sign the other accounts out. The owner chose to keep signed-out accounts in the picker, as Microsoft Entra ID does, so the cookie must keep the ended session IDs.

## Consequences

An ended session ID stays in the browser. It authenticates nothing, because the server stores the end of the session. A "Signed out" row shows an email address on a shared computer until the user forgets it, the browser closes, or 7 days pass. A request with `prompt=none` after a sign-out still gets `login_required`.
