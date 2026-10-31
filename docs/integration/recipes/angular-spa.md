# Recipe: Angular single-page app

[Documentation home](../../documentation.md)

This recipe connects an Angular app to Heimdall as a public client. It uses [`angular-auth-oidc-client`](https://github.com/damienbod/angular-auth-oidc-client), a certified OpenID Connect library. The Heimdall demo SPA (`ui/projects/demo`) uses this setup and signs in end to end.

## Registration

Ask the operator for a client with these settings. See [Register a client](../register-a-client.md).

| Setting | Value |
|---|---|
| Client type | Public |
| Grants | `authorization_code`, `refresh_token` |
| Redirect URI | `https://app.example.com/callback` |
| Scopes | `openid email offline_access` (add your API scopes) |
| Audiences | Your API, if the app calls one |

The `https` redirect URI also gives your origin CORS access to `/token`, `/revoke`, and `/userinfo`.

## Install

```sh
npm install angular-auth-oidc-client
```

## Configuration

```ts
// auth.config.ts
import { LogLevel, OpenIdConfiguration } from 'angular-auth-oidc-client';

export function authConfig(origin: string): OpenIdConfiguration {
  return {
    authority: 'https://acme.example.com',
    clientId: 'orders-web',
    redirectUrl: `${origin}/callback`,
    postLogoutRedirectUri: origin,
    // Authorization code with PKCE S256. The library makes the verifier and the challenge.
    responseType: 'code',
    scope: 'openid email offline_access',
    // Renew with the refresh token, never with a hidden iframe.
    // Heimdall sends frame-ancestors 'none', so an iframe cannot load.
    useRefreshToken: true,
    silentRenew: true,
    renewTimeBeforeTokenExpiresInSeconds: 30,
    // Heimdall sends no new ID token on refresh. The library keeps the first one.
    ignoreNonceAfterRefresh: true,
    triggerRefreshWhenIdTokenExpired: false,
    // A refresh token is single use. Never send one twice.
    allowUnsafeReuseRefreshToken: false,
    logLevel: LogLevel.Warn,
  };
}
```

Each setting and the reason for it:

| Setting | Reason |
|---|---|
| `responseType: 'code'` | Heimdall supports only the authorization code flow. |
| `useRefreshToken: true` | Heimdall pages refuse to load in a frame, so iframe silent renew fails. |
| `ignoreNonceAfterRefresh: true` | A refresh response has no ID token. Without this setting, the library looks for a nonce that is not there. |
| `triggerRefreshWhenIdTokenExpired: false` | The ID token expires with the first access token. A refresh does not replace it, so the library must not refresh because of it. |
| `allowUnsafeReuseRefreshToken: false` | Heimdall revokes the family when a refresh token is used twice. |

## Keep tokens in memory

By default, the library stores tokens in `sessionStorage`. Any script on the page can read web storage. A cross-site scripting bug would then leak the refresh token.

Keep tokens in memory. Keep in `sessionStorage` only the values that must survive the redirect to Heimdall and back:

```ts
// split-storage.ts
import { AbstractSecurityStorage } from 'angular-auth-oidc-client';

/** The library keys that must survive the page load at /callback. Everything else stays in memory. */
const REDIRECT_KEYS: readonly string[] = [
  'authStateControl',
  'authNonce',
  'codeVerifier',
  'storageCodeFlowInProgress',
  'storageCustomParamsAuthRequest',
  'authWellKnownEndPoints',
];

const SESSION_PREFIX = 'app.oidc-flow.';

type Entries = Record<string, unknown>;

export class SplitSecurityStorage implements AbstractSecurityStorage {
  private readonly memory = new Map<string, Entries>();

  constructor(private readonly session: Storage) {}

  read(configId: string): string | null {
    const merged = { ...this.readSession(configId), ...this.memory.get(configId) };
    return Object.keys(merged).length === 0 ? null : JSON.stringify(merged);
  }

  write(configId: string, value: string): void {
    const entries = (JSON.parse(value) ?? {}) as Entries;
    const forSession: Entries = {};
    const forMemory: Entries = {};
    for (const [key, entry] of Object.entries(entries)) {
      (REDIRECT_KEYS.includes(key) ? forSession : forMemory)[key] = entry;
    }
    this.memory.set(configId, forMemory);
    if (Object.keys(forSession).length === 0) {
      this.session.removeItem(SESSION_PREFIX + configId);
    } else {
      this.session.setItem(SESSION_PREFIX + configId, JSON.stringify(forSession));
    }
  }

  remove(configId: string): void {
    this.memory.delete(configId);
    this.session.removeItem(SESSION_PREFIX + configId);
  }

  clear(): void {
    this.memory.clear();
    for (const key of Object.keys(this.session)) {
      if (key.startsWith(SESSION_PREFIX)) {
        this.session.removeItem(key);
      }
    }
  }

  private readSession(configId: string): Entries {
    const raw = this.session.getItem(SESSION_PREFIX + configId);
    return raw === null ? {} : (JSON.parse(raw) as Entries);
  }
}
```

The list is an allowlist. A new key in a later library version stays in memory by default. The demo SPA has the full version with tests in `ui/projects/demo/src/app/auth/split-storage.ts`.

With tokens in memory, each browser tab has its own sign-in and its own refresh token family. Two tabs never send the same refresh token, so the false reuse problem in [Refresh tokens](../refresh-tokens.md#avoid-false-reuse) does not happen.

## Providers

```ts
// app.config.ts
import { provideHttpClient } from '@angular/common/http';
import { ApplicationConfig, inject, provideAppInitializer } from '@angular/core';
import { provideRouter } from '@angular/router';
import { AbstractSecurityStorage, OidcSecurityService, provideAuth } from 'angular-auth-oidc-client';
import { firstValueFrom } from 'rxjs';
import { routes } from './app.routes';
import { authConfig } from './auth/auth.config';
import { SplitSecurityStorage } from './auth/split-storage';

export const appConfig: ApplicationConfig = {
  providers: [
    provideHttpClient(),
    provideAuth({ config: authConfig(window.location.origin) }),
    { provide: AbstractSecurityStorage, useFactory: () => new SplitSecurityStorage(sessionStorage) },
    // Finish the callback before the router reads the URL.
    provideAppInitializer(() => firstValueFrom(inject(OidcSecurityService).checkAuth(window.location.href))),
    provideRouter(routes),
  ],
};
```

## Sign in and sign out

```ts
import { inject } from '@angular/core';
import { OidcSecurityService } from 'angular-auth-oidc-client';
import { firstValueFrom } from 'rxjs';

export class AuthActions {
  private readonly oidc = inject(OidcSecurityService);

  signIn(): void {
    this.oidc.authorize();
  }

  async signOut(): Promise<void> {
    try {
      // Revokes the refresh token family at Heimdall (RFC 7009).
      // Do this first, so the family ends even if the user does not confirm the sign-out.
      await firstValueFrom(this.oidc.revokeRefreshToken());
    } catch {
      // The sign-out at Heimdall revokes the family too.
    }
    // Sends the browser to the end_session_endpoint with id_token_hint and post_logout_redirect_uri.
    await firstValueFrom(this.oidc.logoff());
  }
}
```

`logoff()` reads `end_session_endpoint` from discovery. Heimdall ends its session and every token family of that session. Then it sends the browser to `postLogoutRedirectUri`. Register that URI in `post_logout_redirect_uris`, by exact match. See [Sign out](../sign-out.md).

`logoffLocal()` ends the session in the app only. The Heimdall session stays valid, so the next `authorize()` signs the user in with no login page.

## After a page reload

Memory is empty after a reload, so the app has no tokens. Send the user to `/authorize` again. If the Heimdall session is still valid, Heimdall returns a new code with no login page, and the user sees only a short redirect.

The demo SPA keeps a flag in `sessionStorage` that means "the user was signed in". The flag holds no token. On start, if the flag is set and the app has no tokens, the app calls `authorize()` at once. See `ui/projects/demo/src/app/auth/demo-session.ts`.

## Call your API

Ask for a token for your API with the `resource` parameter. If your client has one registered audience, Heimdall uses it by default. See [Choose the audience](../sign-in-users.md#choose-the-audience).

Send the access token in the `Authorization: Bearer` header. The library's interceptor can do this for the URLs that you list in `secureRoutes`. If your tokens are DPoP-bound (`token_type` `DPoP`), see the next section instead.

## Bind the tokens with DPoP

`angular-auth-oidc-client` has no DPoP support. The demo SPA adds it in about 150 lines, in `ui/projects/demo/src/app/auth/dpop.ts`:

1. Create an ECDSA P-256 key pair with Web Crypto, with `extractable: false`. Keep it in IndexedDB, so it survives the redirect to `/authorize`. Script can sign with a non-extractable key, but cannot read it.
2. Before `authorize()`, compute the key's RFC 7638 thumbprint and pass it: `authorize(undefined, { customParams: { dpop_jkt } })`.
3. Add an `HttpInterceptorFn` that adds a `DPoP` proof header to each `POST` to the token endpoint. The library sends its token requests through Angular's `HttpClient`, so the interceptor sees them.
4. Call your API (and `/userinfo`) with `Authorization: DPoP <token>` and a new proof that has `ath`. Do not use the library's `secureRoutes` interceptor for bound tokens: it sends `Bearer`, and Heimdall refuses a bound token with `Bearer`.

See [DPoP](../dpop.md) for the proof rules.

## Known gaps

- We have not confirmed that `angular-auth-oidc-client` checks the `iss` parameter in the authorization response (RFC 9207). If your app trusts more than one identity provider, check `iss` yourself before `checkAuth`.
- `email_verified` is always `false`. Do not treat the email address as verified.
