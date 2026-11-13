# DR-015: Phase 3 starts with account features, for one shared tenant

- Date: 2026-11-14
- Status: Accepted. Decided by the owner, in the Asgard suite review (suite decisions S2, S3 and S7 in `Asgard/docs/decisions.md`).
- Affects: the roadmap (the order of Phase 3). No decision in the threat model changes. The new work needs new decisions and tables, which get their rows when it is designed.

## Before

Phase 3 was "breadth": tenant administration, WebAuthn, the admin portal, the audit log, consent management and the client libraries, starting with the account picker (#41). Registration, email verification, password reset and account recovery were out of scope, with a note in the threat model to add them before any public deployment. Heimdall was a portfolio project with a plan to reuse it for the owner's other projects.

## After

Heimdall is the sign-in service of the Asgard suite's online group. Three things follow.

1. **Account features come first in Phase 3,** after the account picker work in progress: registration, email verification, password reset and account recovery. Each gets its threat-model section and its tables first, as the threat model already requires.
2. **Everyone signs up in one tenant.** A household is not a tenant. Registration is open, and "who may register" is a tenant setting, so it can be closed later. Tenant administration and onboarding for other organisations stay in Phase 3, after the account features.
3. **A home is a client.** Bifröst, the suite's home service, signs its admin in with the authorization code flow and PKCE as a public client, with a loopback redirect URI. `RedirectUriRules` already allows loopback `http`. Every home uses the same client. The home then asks for access tokens for Huginn with the `resource` parameter (D22).

Heimdall is not installed in homes. There is no "lite" profile, no second storage provider and no single-tenant mode.

## Reason

Friends of the owner will use Huginn, and their homes will link to their accounts. Nobody but the developer can get an account today: users come from `seed-dev`. One tenant is needed because each tenant has its own user pool (D19), and people in separate pools could not share one Huginn. A home needs no Heimdall of its own: it pairs devices and only needs to prove who its admin is to the online group.

## Consequences

- Registration and recovery are the most common route to account takeover. They need the same care as the token endpoints: one answer for a known and an unknown email, throttling (D5 and the login throttle), and verified email before an account can be used.
- A mail sender becomes a dependency. Heimdall has none today.
- The breached-password check (D14, listed in the threat model's open items) is built with registration and password change.
- A public client with a loopback redirect is new for Heimdall's seed and docs. Loopback ports vary, so the port rule for loopback redirect URIs must be decided (RFC 8252, section 7.3) and recorded as a decision.
- Refresh-token reuse revokes the family (DR-003). A home that restores an old backup of its token will be signed out and must link again. That is correct, and Bifröst's docs must say so.
- The owner now operates a service that holds other people's accounts. Backups, the runbook and Phase 4 matter sooner.
