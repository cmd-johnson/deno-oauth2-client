// deno-lint-ignore-file no-explicit-any
import {
  assertEquals,
  assertRejects,
} from "https://deno.land/std@0.161.0/testing/asserts.ts";
import {
  assertSpyCall,
  assertSpyCallAsync,
  assertSpyCalls,
  spy,
} from "https://deno.land/std@0.161.0/testing/mock.ts";

import { AuthorizationResponseError, OAuth2ResponseError } from "./errors.ts";
import {
  assertMatchesUrl,
  buildImplicitAccessTokenCallback,
  getOAuth2Client,
} from "./test_utils.ts";

//#region ImplicitGrant.getAuthorizationUri successful paths

Deno.test("ImplicitGrant.getAuthorizationUri works without additional options", () => {
  assertMatchesUrl(
    getOAuth2Client().implicit.getAuthorizationUri(),
    "https://auth.server/auth?response_type=token&client_id=clientId",
  );
});

Deno.test("ImplicitGrant.getAuthorizationUri when passing a single scope", () => {
  assertMatchesUrl(
    getOAuth2Client().implicit.getAuthorizationUri({
      scope: "singleScope",
    }),
    "https://auth.server/auth?response_type=token&client_id=clientId&scope=singleScope",
  );
});

Deno.test("ImplicitGrant.getAuthorizationUri when passing multiple scopes", () => {
  assertMatchesUrl(
    getOAuth2Client().implicit.getAuthorizationUri({
      scope: ["multiple", "scopes"],
    }),
    "https://auth.server/auth?response_type=token&client_id=clientId&scope=multiple+scopes",
  );
});

Deno.test("ImplicitGrant.getAuthorizationUri works when passing a state parameter", () => {
  assertMatchesUrl(
    getOAuth2Client().implicit.getAuthorizationUri({
      state: "someState",
    }),
    "https://auth.server/auth?response_type=token&client_id=clientId&state=someState",
  );
});

Deno.test("ImplicitGrant.getAuthorizationUri works with redirectUri", () => {
  assertMatchesUrl(
    getOAuth2Client({
      redirectUri: "https://example.app/redirect",
    }).implicit.getAuthorizationUri(),
    "https://auth.server/auth?response_type=token&client_id=clientId&redirect_uri=https%3A%2F%2Fexample.app%2Fredirect",
  );
});

Deno.test("ImplicitGrant.getAuthorizationUri works with redirectUri and a single scope", () => {
  assertMatchesUrl(
    getOAuth2Client({
      redirectUri: "https://example.app/redirect",
    }).implicit.getAuthorizationUri({
      scope: "singleScope",
    }),
    "https://auth.server/auth?response_type=token&client_id=clientId&redirect_uri=https%3A%2F%2Fexample.app%2Fredirect&scope=singleScope",
  );
});

Deno.test("ImplicitGrant.getAuthorizationUri works with redirectUri and multiple scopes", () => {
  assertMatchesUrl(
    getOAuth2Client({
      redirectUri: "https://example.app/redirect",
    }).implicit.getAuthorizationUri({
      scope: ["multiple", "scopes"],
    }),
    "https://auth.server/auth?response_type=token&client_id=clientId&redirect_uri=https%3A%2F%2Fexample.app%2Fredirect&scope=multiple+scopes",
  );
});

Deno.test("ImplicitGrant.getAuthorizationUri uses default scopes if no scope was specified", () => {
  assertMatchesUrl(
    getOAuth2Client({
      defaults: { scope: ["default", "scopes"] },
    }).implicit.getAuthorizationUri(),
    "https://auth.server/auth?response_type=token&client_id=clientId&scope=default+scopes",
  );
});

Deno.test("ImplicitGrant.getAuthorizationUri uses specified scopes over default scopes", () => {
  assertMatchesUrl(
    getOAuth2Client({
      defaults: { scope: ["default", "scopes"] },
    }).implicit.getAuthorizationUri({
      scope: "notDefault",
    }),
    "https://auth.server/auth?response_type=token&client_id=clientId&scope=notDefault",
  );
});

//#endregion

//#region ImplicitGrant.getToken error paths

Deno.test("ImplicitGrant.getToken throws if the received redirectUri does not match the configured one", async () => {
  await assertRejects(
    () =>
      getOAuth2Client({
        redirectUri: "https://example.com/redirect",
      }).implicit.getToken(
        buildImplicitAccessTokenCallback({
          baseUrl: "https://example.com/invalid-redirect",
        }),
      ),
    AuthorizationResponseError,
    "redirect path should match configured path",
  );
});

Deno.test("ImplicitGrant.getToken throws if the callbackUri does not contain any parameters", async () => {
  await assertRejects(
    () =>
      getOAuth2Client().implicit.getToken(
        buildImplicitAccessTokenCallback(),
      ),
    AuthorizationResponseError,
    "URI does not contain callback fragment parameters",
  );
});

Deno.test("ImplicitGrant.getToken throws if the callbackUri contains an error parameter", async () => {
  await assertRejects(
    () =>
      getOAuth2Client().implicit.getToken(
        buildImplicitAccessTokenCallback({
          params: { error: "invalid_request" },
        }),
      ),
    OAuth2ResponseError,
    "invalid_request",
  );
});

Deno.test("ImplicitGrant.getToken throws if the callbackUri contains the error, error_description and error_uri parameters and adds them to the error object", async () => {
  const error = await assertRejects(
    () =>
      getOAuth2Client().implicit.getToken(
        buildImplicitAccessTokenCallback({
          params: {
            error: "invalid_request",
            error_description: "Error description",
            error_uri: "error://uri",
          },
        }),
      ),
    OAuth2ResponseError,
    "Error description",
  ) as OAuth2ResponseError;
  assertEquals(error.error, "invalid_request");
  assertEquals(error.errorDescription, "Error description");
  assertEquals(error.errorUri, "error://uri");
});

Deno.test("ImplicitGrant.getToken throws if the callbackUri doesn't contain an access_token", async () => {
  await assertRejects(
    () =>
      getOAuth2Client().implicit.getToken(
        buildImplicitAccessTokenCallback({
          // some parameter has to be set or we'll get "URI does not contain callback parameters" instead
          params: { empty: "" } as any,
        }),
      ),
    AuthorizationResponseError,
    "missing access_token",
  );
});

Deno.test("ImplicitGrant.getToken throws if it didn't receive an access_token", async () => {
  await assertRejects(
    () =>
      getOAuth2Client().implicit.getToken(
        buildImplicitAccessTokenCallback({
          params: { token_type: "Bearer" },
        }),
      ),
    AuthorizationResponseError,
    "missing access_token",
  );
});

Deno.test("ImplicitGrant.getToken throws if it didn't receive a token_type", async () => {
  await assertRejects(
    () =>
      getOAuth2Client().implicit.getToken(
        buildImplicitAccessTokenCallback({
          params: { access_token: "token" },
        }),
      ),
    AuthorizationResponseError,
    "missing token_type",
  );
});

Deno.test("ImplicitGrant.getToken throws if it didn't receive a state and the state validator fails", async () => {
  await assertRejects(
    () =>
      getOAuth2Client().implicit.getToken(
        buildImplicitAccessTokenCallback({
          params: { access_token: "at", token_type: "Bearer" },
        }),
        { stateValidator: () => false },
      ),
    AuthorizationResponseError,
    "missing state",
  );
});

Deno.test("ImplicitGrant.getToken throws if it didn't receive a state and the async state validator fails", async () => {
  await assertRejects(
    () =>
      getOAuth2Client().implicit.getToken(
        buildImplicitAccessTokenCallback({
          params: { access_token: "at", token_type: "Bearer" },
        }),
        { stateValidator: () => Promise.resolve(false) },
      ),
    AuthorizationResponseError,
    "missing state",
  );
});

Deno.test("ImplicitGrant.getToken throws if it didn't receive a state and the default async state validator fails", async () => {
  await assertRejects(
    () =>
      getOAuth2Client({
        defaults: { stateValidator: () => Promise.resolve(false) },
      }).implicit.getToken(
        buildImplicitAccessTokenCallback({
          params: { access_token: "at", token_type: "Bearer" },
        }),
      ),
    AuthorizationResponseError,
    "missing state",
  );
});

Deno.test("ImplicitGrant.getToken throws if it didn't receive a state but a state was expected", async () => {
  await assertRejects(
    () =>
      getOAuth2Client().implicit.getToken(
        buildImplicitAccessTokenCallback({
          params: { access_token: "at", token_type: "Bearer" },
        }),
        { state: "expected_state" },
      ),
    AuthorizationResponseError,
    "missing state",
  );
});

Deno.test("ImplicitGrant.getToken throws if it received a state that does not match the given state parameter", async () => {
  await assertRejects(
    () =>
      getOAuth2Client().implicit.getToken(
        buildImplicitAccessTokenCallback({
          params: {
            access_token: "at",
            token_type: "Bearer",
            state: "invalid_state",
          },
        }),
        { state: "expected_state" },
      ),
    AuthorizationResponseError,
    "invalid state: invalid_state",
  );
});

Deno.test("ImplicitGrant.getToken throws if the stateValidator returns false", async () => {
  await assertRejects(
    () =>
      getOAuth2Client().implicit.getToken(
        buildImplicitAccessTokenCallback({
          params: {
            access_token: "at",
            token_type: "Bearer",
            state: "invalid_state",
          },
        }),
        { stateValidator: () => false },
      ),
    AuthorizationResponseError,
    "invalid state: invalid_state",
  );
});

Deno.test("ImplicitGrant.getToken throws if the async stateValidator returns false", async () => {
  await assertRejects(
    () =>
      getOAuth2Client().implicit.getToken(
        buildImplicitAccessTokenCallback({
          params: {
            access_token: "at",
            token_type: "Bearer",
            state: "invalid_state",
          },
        }),
        { stateValidator: () => Promise.resolve(false) },
      ),
    AuthorizationResponseError,
    "invalid state: invalid_state",
  );
});

Deno.test("ImplicitGrant.getToken throws if the server response's expires_in property is not a number", async () => {
  await assertRejects(
    () =>
      getOAuth2Client().implicit.getToken(buildImplicitAccessTokenCallback({
        params: {
          access_token: "at",
          token_type: "Bearer",
          expires_in: "invalid",
        },
      })),
    AuthorizationResponseError,
    "expires_in is not a number",
  );
});

//#endregion

//#region ImplicitGrant.getToken successful paths

Deno.test("ImplicitGrant.getToken parses the minimal token response correctly", async () => {
  const result = await getOAuth2Client().implicit.getToken(
    buildImplicitAccessTokenCallback({
      params: { access_token: "accessToken", token_type: "tokenType" },
    }),
  );
  assertEquals(result, {
    accessToken: "accessToken",
    tokenType: "tokenType",
  });
});

Deno.test("ImplicitGrant.getToken parses the full token response correctly", async () => {
  const result = await getOAuth2Client().implicit.getToken(
    buildImplicitAccessTokenCallback({
      params: {
        access_token: "accessToken",
        token_type: "tokenType",
        expires_in: "3600",
        scope: "multiple scopes",
      },
    }),
  );
  assertEquals(result, {
    accessToken: "accessToken",
    tokenType: "tokenType",
    expiresIn: 3600,
    scope: ["multiple", "scopes"],
  });
});

Deno.test("ImplicitGrant.getToken doesn't throw if it didn't receive a state but the state validator returns true", async () => {
  await getOAuth2Client().implicit.getToken(
    buildImplicitAccessTokenCallback({
      params: { access_token: "accessToken", token_type: "tokenType" },
    }),
    { stateValidator: () => true },
  );
});

Deno.test("ImplicitGrant.getToken doesn't throw if it didn't receive a state but the async state validator returns true", async () => {
  await getOAuth2Client().implicit.getToken(
    buildImplicitAccessTokenCallback({
      params: { access_token: "accessToken", token_type: "tokenType" },
    }),
    { stateValidator: () => Promise.resolve(true) },
  );
});

Deno.test("ImplicitGrant.getToken uses the default state validator if no state or validator was given", async () => {
  const defaultValidator = spy(() => true);

  await getOAuth2Client({
    defaults: { stateValidator: defaultValidator },
  }).implicit.getToken(buildImplicitAccessTokenCallback({
    params: {
      access_token: "accessToken",
      token_type: "tokenType",
      state: "some_state",
    },
  }));

  assertSpyCall(defaultValidator, 0, { args: ["some_state"], returned: true });
  assertSpyCalls(defaultValidator, 1);
});

Deno.test("ImplicitGrant.getToken uses the default async state validator if no state or validator was given", async () => {
  const defaultValidator = spy(() => Promise.resolve(true));

  await getOAuth2Client({
    defaults: { stateValidator: defaultValidator },
  }).implicit.getToken(buildImplicitAccessTokenCallback({
    params: {
      access_token: "accessToken",
      token_type: "tokenType",
      state: "some_state",
    },
  }));

  assertSpyCallAsync(defaultValidator, 0, {
    args: ["some_state"],
    returned: true,
  });
  assertSpyCalls(defaultValidator, 1);
});

Deno.test("ImplicitGrant.getToken uses the passed state validator over the default validator", () => {
  const defaultValidator = spy(() => true);
  const validator = spy(() => true);

  getOAuth2Client({
    defaults: { stateValidator: defaultValidator },
  }).implicit.getToken(
    buildImplicitAccessTokenCallback({
      params: {
        access_token: "accessToken",
        token_type: "tokenType",
        state: "some_state",
      },
    }),
    { stateValidator: validator },
  );

  assertSpyCalls(defaultValidator, 0);
  assertSpyCall(validator, 0, { args: ["some_state"], returned: true });
  assertSpyCalls(validator, 1);
});

Deno.test("ImplicitGrant.getToken uses the passed async state validator over the default validator", () => {
  const defaultValidator = spy(() => true);
  const validator = spy(() => Promise.resolve(true));

  getOAuth2Client({
    defaults: { stateValidator: defaultValidator },
  }).implicit.getToken(
    buildImplicitAccessTokenCallback({
      params: {
        access_token: "accessToken",
        token_type: "tokenType",
        state: "some_state",
      },
    }),
    { stateValidator: validator },
  );

  assertSpyCalls(defaultValidator, 0);
  assertSpyCallAsync(validator, 0, { args: ["some_state"], returned: true });
  assertSpyCalls(validator, 1);
});

Deno.test("ImplicitGrant.getToken uses the passed state validator over the passed state", () => {
  const defaultValidator = spy(() => true);
  const validator = spy(() => true);

  getOAuth2Client({
    defaults: { stateValidator: defaultValidator },
  }).implicit.getToken(
    buildImplicitAccessTokenCallback({
      params: {
        access_token: "accessToken",
        token_type: "tokenType",
        state: "some_state",
      },
    }),
    { stateValidator: validator, state: "other_state" },
  );

  assertSpyCalls(defaultValidator, 0);
  assertSpyCall(validator, 0, { args: ["some_state"], returned: true });
  assertSpyCalls(validator, 1);
});

//#endregion
