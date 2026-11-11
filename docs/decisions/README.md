# Decision records

The current decisions are in the decision tables: D1 to D50 in the [threat model](../threat-model.md), and U1 to U17 in the [front-end design](../frontend-design.md). A table shows only what is true now.

A decision record keeps the history. Each record is one change to a decision: what was true before, what is true after, and the reason. A correction to the first draft also gets a record. A new decision gets a row in its table and no record.

## Rules

- Write a record in the same commit as the change.
- Do not change a record after its commit, except to set its status to "Superseded" and name the new record.
- Use the next number. Keep the sections: Before, After, Reason, Consequences.
- Name who decided: the owner, or Claude with the owner's go-ahead.

## Records

| Record | Date | Change |
|---|---|---|
| [DR-001](001-angular-for-all-ui.md) | 2026-10-18 | Angular for all user interfaces |
| [DR-002](002-claude-writes-the-implementation.md) | 2026-10-18 | Claude writes the implementation |
| [DR-003](003-code-reuse-revokes-the-family.md) | 2026-10-18 | Code reuse revokes the token family |
| [DR-004](004-exact-redirect-uris-no-implicit.md) | 2026-10-18 | Follow RFC 9700: no implicit flow, exact redirect URIs |
| [DR-005](005-signing-keys-and-token-tables.md) | 2026-10-18 | Signing keys for each tenant, and a table for token families |
| [DR-006](006-rls-tenant-set-at-connection-open.md) | 2026-10-19 | Row-level security sets the tenant when a connection opens |
| [DR-007](007-visual-direction.md) | 2026-10-19 to 2026-10-25 | Visual direction of the account pages: U13, then U15, then U16 |
| [DR-008](008-self-hosted-fonts-in-csp.md) | 2026-10-23 | The account pages may load fonts from Heimdall's own origin |
| [DR-009](009-keep-pkce-for-all-and-patch-the-suite.md) | 2026-10-28 | Keep PKCE for all clients and patch the conformance suite |
| [DR-010](010-userinfo-reads-the-family.md) | 2026-10-28 | /userinfo reads the token family (D44) |
| [DR-011](011-private-key-jwt.md) | 2026-10-28 | Confidential clients can use private_key_jwt |
| [DR-012](012-pnpm-replaces-npm.md) | 2026-10-31 | pnpm replaces npm for the Angular workspace |
| [DR-013](013-several-sessions-in-one-browser.md) | 2026-11-12 | One browser holds several sessions (#41) |
