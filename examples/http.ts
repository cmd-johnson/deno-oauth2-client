import {
  type Cookie,
  deleteCookie,
  getCookies,
  setCookie,
} from "@std/http/cookie";
import { OAuth2Client } from "@cmd-johnson/deno-oauth2-client";

const oauth2Client = new OAuth2Client({
  clientId: Deno.env.get("CLIENT_ID")!,
  clientSecret: Deno.env.get("CLIENT_SECRET")!,
  authorizationEndpointUri: "https://github.com/login/oauth/authorize",
  tokenUri: "https://github.com/login/oauth/access_token",
  redirectUri: "http://localhost:8000/oauth2/callback",
  defaults: {
    scope: "read:user",
  },
});

/** This is where we'll store our state and PKCE codeVerifiers */
const loginStates = new Map<string, { state: string; codeVerifier: string }>();
/** The name we'll use for the session cookie */
const cookieName = "session";

/** Handles incoming HTTP requests */
function handler(req: Request): Promise<Response> | Response {
  const url = new URL(req.url);
  const path = url.pathname;

  switch (path) {
    case "/login":
      return redirectToAuthEndpoint();
    case "/oauth2/callback":
      return handleCallback(req);
    default:
      return new Response("Not Found", { status: 404 });
  }
}

async function redirectToAuthEndpoint(): Promise<Response> {
  // Generate a random state
  const state = crypto.randomUUID();

  const { uri, codeVerifier } = await oauth2Client.code.getAuthorizationUri({
    state,
  });

  // Associate the state and PKCE codeVerifier with a session cookie
  const sessionId = crypto.randomUUID();
  loginStates.set(sessionId, { state, codeVerifier });
  const sessionCookie: Cookie = {
    name: cookieName,
    value: sessionId,
    httpOnly: true,
    sameSite: "Lax",
  };
  const headers = new Headers({ Location: uri.toString() });
  setCookie(headers, sessionCookie);

  // Redirect to the authorization endpoint
  return new Response(null, { status: 302, headers });
}

async function handleCallback(req: Request): Promise<Response> {
  // Load the state and PKCE codeVerifier associated with the session
  const sessionCookie = getCookies(req.headers)[cookieName];
  const loginState = sessionCookie && loginStates.get(sessionCookie);
  if (!loginState) {
    throw new Error("invalid session");
  }
  loginStates.delete(sessionCookie);

  // Exchange the authorization code for an access token
  const tokens = await oauth2Client.code.getToken(req.url, loginState);

  // Use the access token to make an authenticated API request
  const userResponse = await fetch("https://api.github.com/user", {
    headers: {
      Authorization: `Bearer ${tokens.accessToken}`,
    },
  });
  const { login } = await userResponse.json();

  // Clear the session cookie since we don't need it anymore
  const headers = new Headers();
  deleteCookie(headers, cookieName);
  return new Response(`Hello, ${login}!`);
}

// Start the app
Deno.serve({ port: 8000 }, handler);
