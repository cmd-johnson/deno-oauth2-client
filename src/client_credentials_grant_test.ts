// deno-lint-ignore-file no-explicit-any
import {
  assertEquals,
  assertMatch,
  assertNotMatch,
  assertRejects,
} from "https://deno.land/std@0.203.0/assert/mod.ts";

import {
  MissingClientSecretError,
  OAuth2ResponseError,
  TokenResponseError,
} from "./errors.ts";
import { getOAuth2Client, mockATResponse } from "./test_utils.ts";

//#region ClientCredentialsGrant.getToken error paths

Deno.test("ClientCredentialsGrant.getToken throws when no client secret was configured", async () => {
  await assertRejects(
    () => getOAuth2Client().clientCredentials.getToken(),
    MissingClientSecretError,
    "this grant requires a clientSecret to be set",
  );
});

Deno.test("ClientCredentialsGrant.getToken throws if the server responded with a Content-Type other than application/json", async () => {
  await assertRejects(
    () =>
      mockATResponse(
        () =>
          getOAuth2Client({ clientSecret: "secret" }).clientCredentials
            .getToken(),
        { body: "not json" },
      ),
    TokenResponseError,
    "Invalid token response: Response is not JSON encoded",
  );
});

Deno.test("ClientCredentialsGrant.getToken throws if the server responded with a correctly formatted error", async () => {
  await assertRejects(
    () =>
      mockATResponse(
        () =>
          getOAuth2Client({ clientSecret: "secret" }).clientCredentials
            .getToken(),
        { status: 401, body: { error: "invalid_client" } },
      ),
    OAuth2ResponseError,
    "invalid_client",
  );
});

Deno.test("ClientCredentialsGrant.getToken throws if the server responded with a 4xx or 5xx and the body doesn't contain an error parameter", async () => {
  await assertRejects(
    () =>
      mockATResponse(
        () =>
          getOAuth2Client({ clientSecret: "secret" }).clientCredentials
            .getToken(),
        { status: 401, body: {} },
      ),
    TokenResponseError,
    "Invalid token response: Server returned 401 and no error description was given",
  );
});

Deno.test("ClientCredentialsGrant.getToken throws if the server's response is not a JSON object", async () => {
  await assertRejects(
    () =>
      mockATResponse(
        () =>
          getOAuth2Client({ clientSecret: "secret" }).clientCredentials
            .getToken(),
        { body: '""' },
      ),
    TokenResponseError,
    "Invalid token response: body is not a JSON object",
  );
  await assertRejects(
    () =>
      mockATResponse(
        () =>
          getOAuth2Client({ clientSecret: "secret" }).clientCredentials
            .getToken(),
        { body: '["array values?!!"]' },
      ),
    TokenResponseError,
    "Invalid token response: body is not a JSON object",
  );
});

Deno.test("ClientCredentialsGrant.getToken throws if the server's response does not contain a token_type", async () => {
  await assertRejects(
    () =>
      mockATResponse(
        () =>
          getOAuth2Client({ clientSecret: "secret" }).clientCredentials
            .getToken(),
        { body: { access_token: "at" } },
      ),
    TokenResponseError,
    "Invalid token response: missing token_type",
  );
});

Deno.test("ClientCredentialsGrant.getToken throws if the server response's token_type is not a string", async () => {
  await assertRejects(
    () =>
      mockATResponse(
        () =>
          getOAuth2Client({ clientSecret: "secret" }).clientCredentials
            .getToken(),
        {
          body: {
            access_token: "at",
            token_type: 1337 as any,
          },
        },
      ),
    TokenResponseError,
    "Invalid token response: token_type is not a string",
  );
});

Deno.test("ClientCredentialsGrant.getToken throws if the server's response does not contain an access_token", async () => {
  await assertRejects(
    () =>
      mockATResponse(
        () =>
          getOAuth2Client({ clientSecret: "secret" }).clientCredentials
            .getToken(),
        { body: { token_type: "tt" } },
      ),
    TokenResponseError,
    "Invalid token response: missing access_token",
  );
});

Deno.test("ClientCredentialsGrant.getToken throws if the server response's access_token is not a string", async () => {
  await assertRejects(
    () =>
      mockATResponse(
        () =>
          getOAuth2Client({ clientSecret: "secret" }).clientCredentials
            .getToken(),
        {
          body: {
            access_token: 1234 as any,
            token_type: "tt",
          },
        },
      ),
    TokenResponseError,
    "Invalid token response: access_token is not a string",
  );
});

Deno.test("ClientCredentialsGrant.getToken throws if the server response's refresh_token property is not a string", async () => {
  await assertRejects(
    () =>
      mockATResponse(
        () =>
          getOAuth2Client({ clientSecret: "secret" }).clientCredentials
            .getToken(),
        {
          body: {
            access_token: "at",
            token_type: "tt",
            refresh_token: 123 as any,
          },
        },
      ),
    TokenResponseError,
    "Invalid token response: refresh_token is not a string",
  );
});

Deno.test("ClientCredentialsGrant.getToken throws if the server response's expires_in property is not a number", async () => {
  await assertRejects(
    () =>
      mockATResponse(
        () =>
          getOAuth2Client({ clientSecret: "secret" }).clientCredentials
            .getToken(),
        {
          body: {
            access_token: "at",
            token_type: "tt",
            expires_in: { this: "is illegal" } as any,
          },
        },
      ),
    TokenResponseError,
    "Invalid token response: expires_in is not a number",
  );
});

Deno.test("ClientCredentialsGrant.getToken throws if the server response's scope property is not a string", async () => {
  await assertRejects(
    () =>
      mockATResponse(
        () =>
          getOAuth2Client({ clientSecret: "secret" }).clientCredentials
            .getToken(),
        {
          body: {
            access_token: "at",
            token_type: "tt",
            scope: ["scope1", "scope2"] as any,
          },
        },
      ),
    TokenResponseError,
    "Invalid token response: scope is not a string",
  );
});

//#endregion

//#region ClientCredentialsGrant.getToken successful paths

Deno.test("ClientCredentialsGrant.getToken builds a correct request to the token endpoint by default", async () => {
  const { request } = await mockATResponse(
    () =>
      getOAuth2Client({ clientSecret: "secret" }).clientCredentials.getToken(),
  );

  assertEquals(request.url, "https://auth.server/token");
  const body = await request.formData();
  assertEquals(body.get("grant_type"), "client_credentials");
  assertEquals(
    request.headers.get("Content-Type"),
    "application/x-www-form-urlencoded",
  );
  assertEquals(
    request.headers.get("Authorization"),
    "Basic Y2xpZW50SWQ6c2VjcmV0",
  );

  assertEquals([...body.keys()].length, 1);
});

Deno.test("ClientCredentialsGrant.getToken includes the passed scope in the token endpoint request", async () => {
  const { request } = await mockATResponse(
    () =>
      getOAuth2Client({ clientSecret: "secret" }).clientCredentials.getToken({
        scope: "singleScope",
      }),
  );

  assertEquals(request.url, "https://auth.server/token");
  const body = await request.formData();
  assertEquals(body.get("grant_type"), "client_credentials");
  assertEquals(body.get("scope"), "singleScope");
  assertEquals(
    request.headers.get("Content-Type"),
    "application/x-www-form-urlencoded",
  );
  assertEquals(
    request.headers.get("Authorization"),
    "Basic Y2xpZW50SWQ6c2VjcmV0",
  );

  assertEquals([...body.keys()].length, 2);
});

Deno.test("ClientCredentialsGrant.getToken includes the passed scopes in the token endpoint request", async () => {
  const { request } = await mockATResponse(
    () =>
      getOAuth2Client({ clientSecret: "secret" }).clientCredentials.getToken({
        scope: ["multiple", "scopes"],
      }),
  );

  assertEquals(request.url, "https://auth.server/token");
  const body = await request.formData();
  assertEquals(body.get("grant_type"), "client_credentials");
  assertEquals(body.get("scope"), "multiple scopes");
  assertEquals(
    request.headers.get("Content-Type"),
    "application/x-www-form-urlencoded",
  );
  assertEquals(
    request.headers.get("Authorization"),
    "Basic Y2xpZW50SWQ6c2VjcmV0",
  );

  assertEquals([...body.keys()].length, 2);
});

Deno.test("ClientCredentialsGrant.getToken includes default scopes in the token endpoint request", async () => {
  const { request } = await mockATResponse(
    () =>
      getOAuth2Client({
        clientSecret: "secret",
        defaults: { scope: ["default", "scopes"] },
      }).clientCredentials.getToken(),
  );

  assertEquals(request.url, "https://auth.server/token");
  const body = await request.formData();
  assertEquals(body.get("grant_type"), "client_credentials");
  assertEquals(body.get("scope"), "default scopes");
  assertEquals(
    request.headers.get("Content-Type"),
    "application/x-www-form-urlencoded",
  );
  assertEquals(
    request.headers.get("Authorization"),
    "Basic Y2xpZW50SWQ6c2VjcmV0",
  );

  assertEquals([...body.keys()].length, 2);
});

Deno.test("ClientCredentialsGrant.getToken does not include default scopes in the token endpoint request when different scopes were passed", async () => {
  const { request } = await mockATResponse(
    () =>
      getOAuth2Client({
        clientSecret: "secret",
        defaults: { scope: ["default", "scopes"] },
      }).clientCredentials.getToken({ scope: "notDefault" }),
  );

  assertEquals(request.url, "https://auth.server/token");
  const body = await request.formData();
  assertEquals(body.get("grant_type"), "client_credentials");
  assertEquals(body.get("scope"), "notDefault");
  assertEquals(
    request.headers.get("Content-Type"),
    "application/x-www-form-urlencoded",
  );
  assertEquals(
    request.headers.get("Authorization"),
    "Basic Y2xpZW50SWQ6c2VjcmV0",
  );

  assertEquals([...body.keys()].length, 2);
});

Deno.test("ClientCredentialsGrant.getToken uses the default request options", async () => {
  const { request } = await mockATResponse(
    () =>
      getOAuth2Client({
        clientSecret: "secret",
        defaults: {
          requestOptions: {
            headers: {
              "User-Agent": "Custom User Agent",
              "Content-Type": "application/json",
            },
            urlParams: { "custom-url-param": "value" },
            body: { "custom-body-param": "value" },
          },
        },
      }).clientCredentials.getToken(),
  );
  const url = new URL(request.url);
  assertEquals(url.searchParams.getAll("custom-url-param"), ["value"]);
  assertEquals(request.headers.get("Content-Type"), "application/json");
  assertEquals(request.headers.get("User-Agent"), "Custom User Agent");
  assertMatch(await request.text(), /.*custom-body-param=value.*/);
});

Deno.test("ClientCredentialsGrant.getToken uses the passed request options over the default options", async () => {
  const { request } = await mockATResponse(
    () =>
      getOAuth2Client({
        clientSecret: "secret",
        defaults: {
          requestOptions: {
            headers: {
              "User-Agent": "Custom User Agent",
              "Content-Type": "application/json",
            },
            urlParams: { "custom-url-param": "value" },
            body: { "custom-body-param": "value" },
          },
        },
      }).clientCredentials.getToken({
        requestOptions: {
          headers: { "Content-Type": "text/plain" },
          urlParams: { "custom-url-param": "other_value" },
          body: { "custom-body-param": "other_value" },
        },
      }),
  );
  const url = new URL(request.url);
  assertEquals(url.searchParams.getAll("custom-url-param"), ["other_value"]);
  assertEquals(request.headers.get("Content-Type"), "text/plain");
  assertEquals(request.headers.get("User-Agent"), "Custom User Agent");

  const requestText = await request.text();
  assertMatch(requestText, /.*custom-body-param=other_value.*/);
  assertNotMatch(requestText, /.*custom-body-param=value.*/);
});

Deno.test("ClientCredentialsGrant.getToken parses the minimal token response correctly", async () => {
  const { result } = await mockATResponse(
    () =>
      getOAuth2Client({ clientSecret: "secret" }).clientCredentials.getToken(),
    {
      body: {
        access_token: "accessToken",
        token_type: "tokenType",
      },
    },
  );
  assertEquals(result, {
    accessToken: "accessToken",
    tokenType: "tokenType",
  });
});

Deno.test("ClientCredentialsGrant.getToken parses the full token response correctly", async () => {
  const { result } = await mockATResponse(
    () =>
      getOAuth2Client({ clientSecret: "secret" }).clientCredentials.getToken(),
    {
      body: {
        access_token: "accessToken",
        token_type: "tokenType",
        refresh_token: "refreshToken",
        expires_in: 3600,
        scope: "multiple scopes",
      },
    },
  );
  assertEquals(result, {
    accessToken: "accessToken",
    tokenType: "tokenType",
    refreshToken: "refreshToken",
    expiresIn: 3600,
    scope: ["multiple", "scopes"],
  });
});

//#endregion
