import { assertEquals, assertMatch } from "@std/assert";
import { returnsNext, stub } from "@std/testing/mock";

import { _internals as pkceInternals, createPkceChallenge } from "./pkce.ts";

/**
 * Returns the byte array from the example in https://www.rfc-editor.org/rfc/rfc7636#appendix-B
 */
function getExampleBytes(): Uint8Array {
  return new Uint8Array([
    116,
    24,
    223,
    180,
    151,
    153,
    224,
    37,
    79,
    250,
    96,
    125,
    216,
    173,
    187,
    186,
    22,
    212,
    37,
    77,
    105,
    214,
    191,
    240,
    91,
    88,
    5,
    88,
    83,
    132,
    141,
    121,
  ]);
}

Deno.test("createPkceChallenge correctly builds a codeChallenge and codeVerifier", async () => {
  const getRandomBytesStub = stub(
    pkceInternals,
    "getRandomBytes",
    returnsNext([getExampleBytes()]),
  );
  try {
    const { codeVerifier, codeChallenge, codeChallengeMethod } =
      await createPkceChallenge();

    assertEquals(codeChallengeMethod, "S256");
    assertEquals(codeVerifier, "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
    assertEquals(codeChallenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
  } finally {
    getRandomBytesStub.restore();
  }
});

Deno.test("createPkceChallenge returns random base64url encoded codes", async () => {
  const urlBase64Regex = /^[a-z0-9_-]{43}$/i;

  const verifiers = new Set<string>();
  const challenges = new Set<string>();

  for (let i = 0; i < 1000; i++) {
    const { codeVerifier, codeChallenge } = await createPkceChallenge();

    assertEquals(verifiers.has(codeVerifier), false);
    assertEquals(challenges.has(codeChallenge), false);
    verifiers.add(codeVerifier);
    verifiers.add(codeChallenge);

    assertMatch(codeVerifier, urlBase64Regex);
    assertMatch(codeChallenge, urlBase64Regex);
  }
});
