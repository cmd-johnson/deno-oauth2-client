# OAuth2 Client for Deno

![Tests](https://github.com/cmd-johnson/deno-oauth2-client/workflows/Tests/badge.svg)
[![deno doc](https://doc.deno.land/badge.svg)](https://doc.deno.land/https/raw.githubusercontent.com/cmd-johnson/deno-oauth2-client/master/mod.ts)

Minimalistic OAuth 2.0 client for Deno. Inspired by
[js-client-oauth2](https://github.com/mulesoft/js-client-oauth2/).

This module tries not to make assumptions on your use-cases. As such, it

- has no external dependencies outside of Deno's standard library
- can be used with Deno's [http module](https://deno.land/std@0.71.0/http) or
  any other library for handling http requests, like
  [oak](https://deno.land/x/oak)
- only implements OAuth 2.0 grants, letting you take care of storing and
  retrieving sessions, managing state parameters, etc.

Currently supported OAuth 2.0 grants:

- [Authorization Code Grant (for clients with and without client secrets)](https://www.rfc-editor.org/rfc/rfc6749#section-4.1)
  - Out of the box support for
    [Proof Key for Code Exchange (PKCE)](https://www.rfc-editor.org/rfc/rfc7636)
- [Implicit Grant](https://www.rfc-editor.org/rfc/rfc6749#section-4.2)
- [Resource Owner Password Credentials Grant](https://www.rfc-editor.org/rfc/rfc6749#section-4.3)
- [Client Credentials Grant](https://www.rfc-editor.org/rfc/rfc6749#section-4.4)
- [Refresh Tokens](https://www.rfc-editor.org/rfc/rfc6749#section-6)

## Usage

### GitHub API example using [oak](https://deno.land/x/oak)

```ts
import { Application, Router } from "https://deno.land/x/oak@v11.1.0/mod.ts";
import { Session } from "https://deno.land/x/oak_sessions@v4.0.5/mod.ts";
import { OAuth2Client } from "https://deno.land/x/oauth2_client/mod.ts";

const oauth2Client = new OAuth2Client({
  clientId: Deno.env.get("CLIENT_ID")!,
  clientSecret: Deno.env.get("CLIENT_SECRET")!,
  authorizationEndpointUri: "https://github.com/login/oauth/authorize",
  tokenUri: "https://github.com/login/oauth/access_token",
  redirectUri: "http://localhost:8000/oauth2/callback",
  scope: "read:user",
});

type AppState = {
  session: Session;
};

const router = new Router<AppState>();
router.get("/login", async (ctx) => {
  // Construct the URL for the authorization redirect and get a PKCE codeVerifier
  const { uri, codeVerifier } = await oauth2Client.code.getAuthorizationUri();

  // Store both the state and codeVerifier in the user session
  ctx.state.session.flash("codeVerifier", codeVerifier);

  // Redirect the user to the authorization endpoint
  ctx.response.redirect(uri);
});
router.get("/oauth2/callback", async (ctx) => {
  // Make sure the codeVerifier is present for the user's session
  const codeVerifier = ctx.state.session.get("codeVerifier");
  if (typeof codeVerifier !== "string") {
    throw new Error("invalid codeVerifier");
  }

  // Exchange the authorization code for an access token
  const tokens = await oauth2Client.code.getToken(ctx.request.url, {
    codeVerifier,
  });

  // Use the access token to make an authenticated API request
  const userResponse = await fetch("https://api.github.com/user", {
    headers: {
      Authorization: `Bearer ${tokens.accessToken}`,
    },
  });
  const { login } = await userResponse.json();

  ctx.response.body = `Hello, ${login}!`;
});

const app = new Application<AppState>();
app.use(Session.initMiddleware());
app.use(router.allowedMethods(), router.routes());

await app.listen({ port: 8000 });
```

### More Examples

For more examples, check out the examples directory.

## Migration

### `v0.*.*` -> `v1.*.*`

With `v1.0.0`:

- we introduced PKCE by default for the Authorization Code Grant
- enabled `stateValidator` callbacks to return a Promise, to allow for e.g.
  accessing a database
- cleaned up interface names to prevent name clashes between e.g. the
  `AuthorizationCodeGrant` and `ImplicitGrant` option objects.

#### `AuthorizationCodeGrant`

- The `GetUriOptions` interface was renamed to `AuthorizationUriOptions`
- `getAuthorizationUri(...)` now always returns a `Promise<{ uri: URL }>`
  instead of a plain `URL`.
  - when using PKCE (which is now the default), `getAuthorizationUri(...)`
    returns an object containing both an URI and the `codeVerifier` that you'll
    have to pass to the `getToken(...)` call inside the OAuth 2.0 redirection
    URI handler. Check out the examples on how to achieve that by using session
    cookies.
  - while you should always use PKCE if possible, there are still OAuth 2.0
    servers that don't support it. To opt out of PKCE, pass
    `{ disablePkce: true }` to `getAuthorizationUri`.

#### `ClientCredentialsGrant`

- The `GetClientCredentialsTokenOptions` interface was renamed to
  `ClientCredentialsTokenOptions`

#### `ImplicitGrant`

- The `GetUriOptions` interface was renamed to `ImplicitUriOptions`
- The `GetTokenOptions` interface was renamed to `ImplicitTokenOptions`

#### `ResourceOwnerPasswordCredentialsGrant`

- The `GetROPCTokenOptions` interface was renamed to
  `ResourceOwnerPasswordCredentialsTokenOptions`

#### `RefreshTokenGrant`

- No changes necessary
