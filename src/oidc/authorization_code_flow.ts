import {
  AuthorizationCodeGrant,
  AuthorizationCodeTokenOptions,
  AuthorizationUri,
  AuthorizationUriOptions,
  AuthorizationUriOptionsWithoutPKCE,
  AuthorizationUriOptionsWithPKCE,
  AuthorizationUriWithoutVerifier,
  AuthorizationUriWithVerifier,
} from "../authorization_code_grant.ts";
import { TokenResponseError } from "../errors.ts";
import { OIDCClientConfig } from "./oidc_client.ts";
import { IDToken, JWTPayload, OIDCTokens } from "./types.ts";
import { encode as base64Encode } from "https://deno.land/std@0.161.0/encoding/base64.ts";

type ValueOrArray<T> = T | T[];
function valueOrArrayToArray<T>(
  value: ValueOrArray<T & (T extends unknown[] ? never : T)>,
): T[] {
  return Array.isArray(value) ? value : [value];
}

/**
 * https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.1.2.1
 */
export interface OIDCAuthorizationUriOptions {
  /**
   * String value used to associate a Client session with an ID Token, and to
   * mitigate replay attacks. The value is passed through unmodified from the
   * Authentication Request to the ID Token. Sufficient entropy MUST be present
   * in the nonce values used to prevent attackers from guessing values.
   */
  nonce?: string;
  /**
   * specifies how the Authorization Server displays the authentication and consent user interface pages to the End-User. The defined values are:
   *
   * - page: The Authorization Server SHOULD display the authentication and consent UI consistent with a full User Agent page view. If the display parameter is not specified, this is the default display mode.
   * - popup: The Authorization Server SHOULD display the authentication and consent UI consistent with a popup User Agent window. The popup User Agent window should be of an appropriate size for a login-focused dialog and should not obscure the entire window that it is popping up over.
   * - The Authorization Server SHOULD display the authentication and consent UI consistent with a device that leverages a touch interface.
   * - The Authorization Server SHOULD display the authentication and consent UI consistent with a "feature phone" type display.
   */
  display?: "page" | "popup" | "touch" | "wap";

  /**
   * specifies whether the Authorization Server prompts the End-User for reauthentication and consent. The defined values are:
   * - none: The Authorization Server MUST NOT display any authentication or consent user interface pages. An error is returned if an End-User is not already authenticated or the Client does not have pre-configured consent for the requested Claims or does not fulfill other conditions for processing the request. The error code will typically be login_required, interaction_required, or another code defined in {@link https://openid.net/specs/openid-connect-core-1_0.html#AuthError Section 3.1.2.6}. This can be used as a method to check for existing authentication and/or consent.
   * - login: The Authorization Server SHOULD prompt the End-User for reauthentication. If it cannot reauthenticate the End-User, it MUST return an error, typically login_required.
   * - consent: The Authorization Server SHOULD prompt the End-User for consent before returning information to the Client. If it cannot obtain consent, it MUST return an error, typically consent_required.
   * - select_account: The Authorization Server SHOULD prompt the End-User to select a user account. This enables an End-User who has multiple accounts at the Authorization Server to select amongst the multiple accounts that they might have current sessions for. If it cannot obtain an account selection choice made by the End-User, it MUST return an error, typically account_selection_required.
   */
  prompt?: ValueOrArray<"none" | "login" | "consent" | "select_account">;

  /**
   * Maximum Authentication Age. Specifies the allowable elapsed time in
   * seconds since the last time the End-User was actively authenticated by the
   * OP. If the elapsed time is greater than this value, the OP MUST attempt to
   * actively re-authenticate the End-User. When maxAge is used, the ID Token
   * returned MUST include an auth_time Claim Value.
   */
  maxAge?: number;

  /**
   * End-User's preferred languages and scripts for the user interface,
   * represented as a space-separated list of {@link https://www.rfc-editor.org/rfc/rfc5646 RFC5646}
   * language tag values, ordered by preference.
   */
  uiLocales?: ValueOrArray<string>;

  /**
   * ID Token previously issued by the Authorization Server being passed as a
   * hint about the End-User's current or past authenticated session with the
   * Client. If the End-User identified by the ID Token is logged in or is
   * logged in by the request, then the Authorization Server returns a positive
   * response; otherwise, it SHOULD return an error, such as login_required.
   * When possible, an id_token_hint SHOULD be present when prompt=none is used
   * and an invalid_request error MAY be returned if it is not; however, the
   * server SHOULD respond successfully when possible, even if it is not
   * present. The Authorization Server need not be listed as an audience of the
   * ID Token when it is used as an id_token_hint value.
   */
  idTokenHint?: string;

  /**
   * Hint to the Authorization Server about the login identifier the End-User
   * might use to log in (if necessary). This hint can be used by an RP if it
   * first asks the End-User for their e-mail address (or other identifier) and
   * then wants to pass that value as a hint to the discovered authorization
   * service. It is RECOMMENDED that the hint value match the value used for
   * discovery. This value MAY also be a phone number in the format specified
   * for the phone_number Claim.
   */
  loginHint?: string;

  /**
   * Requested Authentication Context Class Reference values. Space-separated
   * string that specifies the acr values that the Authorization Server is
   * being requested to use for processing this Authentication Request, with the
   * values appearing in order of preference. The Authentication Context Class
   * satisfied by the authentication performed is returned as the acr Claim
   * Value.
   */
  acrValues?: ValueOrArray<string>;
}

export class AuthorizationCodeFlow extends AuthorizationCodeGrant {
  protected readonly config: OIDCClientConfig;

  constructor(config: OIDCClientConfig) {
    super(config);
    this.config = config;
  }

  public getAuthorizationUri(
    options?: AuthorizationUriOptionsWithPKCE & OIDCAuthorizationUriOptions,
  ): Promise<AuthorizationUriWithVerifier>;
  public getAuthorizationUri(
    options: AuthorizationUriOptionsWithoutPKCE & OIDCAuthorizationUriOptions,
  ): Promise<AuthorizationUriWithoutVerifier>;
  public async getAuthorizationUri(
    options: AuthorizationUriOptions & OIDCAuthorizationUriOptions = {},
  ): Promise<AuthorizationUri> {
    // this may look weird and useless, but it makes TypeScript happy
    const url =
      await (options.disablePkce
        ? super.getAuthorizationUri(options)
        : super.getAuthorizationUri(options));

    if (typeof options.nonce !== "undefined") {
      url.uri.searchParams.set("nonce", options.nonce);
    }
    if (typeof options.display !== "undefined") {
      url.uri.searchParams.set("display", options.display);
    }
    if (typeof options.prompt !== "undefined") {
      url.uri.searchParams.set(
        "prompt",
        valueOrArrayToArray(options.prompt).join(" "),
      );
    }
    if (typeof options.maxAge !== "undefined") {
      url.uri.searchParams.set("max_age", String(options.maxAge));
    }
    if (typeof options.uiLocales !== "undefined") {
      url.uri.searchParams.set(
        "ui_locales",
        valueOrArrayToArray(options.uiLocales).join(" "),
      );
    }
    if (typeof options.idTokenHint !== "undefined") {
      url.uri.searchParams.set("id_token_hint", options.idTokenHint);
    }
    if (typeof options.loginHint !== "undefined") {
      url.uri.searchParams.set("login_hint", options.loginHint);
    }
    if (typeof options.acrValues !== "undefined") {
      url.uri.searchParams.set(
        "acr_values",
        valueOrArrayToArray(options.acrValues).join(" "),
      );
    }

    return url;
  }

  public async getToken(
    authResponseUri: string | URL,
    options: AuthorizationCodeTokenOptions & { nonce?: string } = {},
  ): Promise<OIDCTokens> {
    const validated = await this.validateAuthorizationResponse(
      this.toUrl(authResponseUri),
      options,
    );

    const request = this.buildAccessTokenRequest(
      validated.code,
      options.codeVerifier,
      options.requestOptions,
    );

    const tokenResponse = await fetch(request);

    const { tokens, body } = await this.parseTokenResponse(tokenResponse);

    if (!("id_token" in body)) {
      throw new TokenResponseError("missing id_token", tokenResponse);
    }
    if (typeof body.id_token !== "string") {
      throw new TokenResponseError("id_token is not a string", tokenResponse);
    }

    const idTokenString = body.id_token;
    const { payload: idToken, protectedHeader } = await this.config.verifyJwt(
      idTokenString,
    );

    this.assertIsValidIDToken(idToken, tokenResponse, options);
    requireOptionalIDTokenClaim(idToken, "at_hash", isString, tokenResponse);
    if (idToken.at_hash) {
      await this.validateAccessToken(
        tokens.accessToken,
        protectedHeader.alg,
        idToken.at_hash,
        tokenResponse,
      );
    }

    return {
      ...tokens,
      idTokenString,
      idToken,
    };
  }

  protected async validateAccessToken(
    accessToken: string,
    joseAlg: string,
    atHash: string,
    tokenResponse: Response,
  ) {
    const accessTokenBytes = new TextEncoder().encode(accessToken);

    const hashAlg = {
      "RS256": "SHA-256",
      "RS384": "SHA-384",
      "RS512": "SHA-512",
    }[joseAlg];
    if (!hashAlg) {
      throw new TokenResponseError(
        `id_token uses unsupported algorithm for signing: ${joseAlg}`,
        tokenResponse,
      );
    }

    const hash = await crypto.subtle.digest(hashAlg, accessTokenBytes);
    const leftHalf = hash.slice(0, hash.byteLength / 2);
    const base64EncodedHash = base64Encode(leftHalf);

    if (base64EncodedHash !== atHash) {
      throw new TokenResponseError(
        `id_token at_hash claim does not match access_token hash`,
        tokenResponse,
      );
    }
  }

  /**
   * Performs ID token payload validation as per Section {@link https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.1.3.7 3.1.3.7.}
   */
  protected assertIsValidIDToken(
    payload: JWTPayload,
    tokenResponse: Response,
    tokenOptions: { nonce?: string },
  ): asserts payload is IDToken {
    const currentTimestamp = Math.floor(Date.now() / 1000);

    // 3.1.3.7.  ID Token Validation
    requireIDTokenClaim(payload, "iss", isString, tokenResponse);
    requireIDTokenClaim(payload, "sub", isString, tokenResponse);
    const isValidAud = (aud: unknown): aud is string | string[] => {
      if (!isStringOrStringArray(aud)) {
        return false;
      }
      return valueOrArrayToArray(aud).some((v) => v === this.config.clientId);
    };
    requireIDTokenClaim(payload, "aud", isValidAud, tokenResponse);
    requireIDTokenClaim(payload, "exp", isNumber, tokenResponse);
    if (payload.exp >= currentTimestamp) {
      throw new TokenResponseError(
        "id_token is already expired",
        tokenResponse,
      );
    }

    requireIDTokenClaim(payload, "iat", isNumber, tokenResponse);
    requireOptionalIDTokenClaim(payload, "auth_time", isNumber, tokenResponse);
    if (typeof tokenOptions.nonce === "string") {
      requireIDTokenClaim(
        payload,
        "nonce",
        (v): v is string => v === tokenOptions.nonce,
        tokenResponse,
      );
    } else if ("nonce" in payload) {
      throw new TokenResponseError(
        "id_token contained a nonce, but none was expected",
        tokenResponse,
      );
    }
    requireOptionalIDTokenClaim(payload, "acr", isString, tokenResponse);
    requireOptionalIDTokenClaim(payload, "amr", isStringArray, tokenResponse);
    requireOptionalIDTokenClaim(
      payload,
      "azp",
      (v): v is string => v === this.config.clientId,
      tokenResponse,
    );
  }
}

function isString(v: unknown): v is string {
  return typeof v === "string";
}
function isStringArray(v: unknown): v is string[] {
  return Array.isArray(v) && v.every(isString);
}
function isStringOrStringArray(v: unknown): v is string | string[] {
  return Array.isArray(v) ? v.every(isString) : isString(v);
}
function isNumber(v: unknown): v is number {
  return typeof v === "number";
}

function requireIDTokenClaim<
  P extends Record<string, unknown>,
  K extends string,
  T,
>(
  payload: P,
  key: K,
  isValid: (value: unknown) => value is T,
  tokenResponse: Response,
): asserts payload is P & { [Key in K]: T } {
  if (!(key in payload)) {
    throw new TokenResponseError(
      `id_token is missing the ${key} claim`,
      tokenResponse,
    );
  }
  if (!isValid(payload[key])) {
    throw new TokenResponseError(
      `id_token contains an invalid ${key} claim`,
      tokenResponse,
    );
  }
}
function requireOptionalIDTokenClaim<
  P extends Record<string, unknown>,
  K extends string,
  T,
>(
  payload: P,
  key: K,
  isValid: (value: unknown) => value is T,
  tokenResponse: Response,
): asserts payload is P & { [Key in K]?: T } {
  if (!(key in payload)) {
    return;
  }
  if (!isValid(payload[key])) {
    throw new TokenResponseError(
      `id_token contains an invalid ${key} claim`,
      tokenResponse,
    );
  }
}
