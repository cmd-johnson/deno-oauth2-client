# OAuth2 Client for Deno

Minimalistic OAuth 2.0 client for Deno.
Inspired by [js-client-oauth2](https://github.com/mulesoft/js-client-oauth2/).

This module tries not to make assumptions on your use-cases.
As such, it
- has no external dependencies (not even Deno's standard library)
- can be used with Deno's [http module](https://deno.land/std@0.71.0/http) or any other library for handling http requests, like [oak](https://deno.land/x/oak)
- only implements OAuth 2.0 grants, letting you take care of storing and retrieving sessions, managing state parameters, etc.

## Usage

### GitHub API example using [oak](https://deno.land/x/oak)

```ts
import { Application, Router } from "https://deno.land/x/oak@v6.3.0/mod.ts";
import { OAuth2Client } from "https://deno.land/x/oauth2_client/mod.ts";

const oauth2Client = new OAuth2Client({
  clientId: "<your client id>",
  clientSecret: "<your client secret>",
  authorizationEndpointUri: "https://github.com/login/oauth/authorize",
  tokenUri: "https://github.com/login/oauth/access_token",
  redirectUri: "http://localhost:8000/oauth2/callback",
  defaults: {
    scope: "read:user",
  },
});

const router = new Router();
router.get("/login", (ctx) => {
  ctx.response.redirect(
    oauth2Client.code.getAuthorizationUri(),
  );
});
router.get("/oauth2/callback", async (ctx) => {
  // Exchange the authorization code for an access token
  const tokens = await oauth2Client.code.getToken(ctx.request.url);

  // Use the access token to make an authenticated API request
  const userResponse = await fetch("https://api.github.com/user", {
    headers: {
      Authorization: `Bearer ${tokens.accessToken}`,
    },
  });
  const { name } = await userResponse.json();

  ctx.response.body = `Hello, ${name}!`;
});

const app = new Application();
app.use(router.allowedMethods(), router.routes());

await app.listen({ port: 8000 });
```

### More Examples

For more examples, check out the examples directory.
