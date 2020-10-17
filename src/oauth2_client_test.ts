import { assert } from "https://deno.land/std@0.71.0/testing/asserts.ts";

import { OAuth2Client } from "./oauth2_client.ts";
import { CodeFlow } from "./code_flow.ts";

Deno.test("OAuth2Client.code is created", () => {
  const client = new OAuth2Client({
    accessTokenUri: "",
    authorizationEndpointUri: "",
    clientId: "",
  });
  assert(client.code instanceof CodeFlow);
});
