import { Application, Router } from "https://deno.land/x/oak@v11.1.0/mod.ts";
import {
  MemoryStore,
  Session,
} from "https://deno.land/x/oak_sessions@v4.0.5/mod.ts";
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
  // Generate a random state for this login event
  const state = crypto.randomUUID();

  // Construct the URL for the authorization redirect and get a PKCE codeVerifier
  const { uri, codeVerifier } = await oauth2Client.code.getAuthorizationUri({
    state,
  });

  // Store both the state and codeVerifier in the user session
  ctx.state.session.flash("state", state);
  ctx.state.session.flash("codeVerifier", codeVerifier);

  // Redirect the user to the authorization endpoint
  ctx.response.redirect(uri);
});
router.get("/oauth2/callback", async (ctx) => {
  // Make sure both a state and codeVerifier are present for the user's session
  const state = ctx.state.session.get("state");
  if (typeof state !== "string") {
    throw new Error("invalid state");
  }

  const codeVerifier = ctx.state.session.get("codeVerifier");
  if (typeof codeVerifier !== "string") {
    throw new Error("invalid codeVerifier");
  }

  // Exchange the authorization code for an access token
  const tokens = await oauth2Client.code.getToken(ctx.request.url, {
    state,
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

// Add a key for signing cookies
app.keys = ["super-secret-key"];

// Set up the session middleware
const sessionStore = new MemoryStore();
app.use(Session.initMiddleware(sessionStore, {
  cookieSetOptions: {
    httpOnly: true,
    sameSite: "lax",
    // Enable for when running outside of localhost
    // secure: true,
    signed: true,
  },
  cookieGetOptions: {
    signed: true,
  },
  expireAfterSeconds: 60 * 10,
}));

// Mount the router
app.use(router.allowedMethods(), router.routes());

// Start the app
const port = 8000;
app.addEventListener("listen", () => {
  console.log(
    `App listening on port ${port}. Navigate to http://localhost:${port}/login to log in!`,
  );
});
await app.listen({ port });
