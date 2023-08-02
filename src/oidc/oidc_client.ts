import { OAuth2ClientConfig } from "../oauth2_client.ts";
import { AuthorizationCodeFlow } from "./authorization_code_flow.ts";
import { IDToken, JWTVerifyResult } from "./types.ts";
import { includesClaim, isObject } from "./validation.ts";

export interface OIDCClientConfig extends OAuth2ClientConfig {
  /** The URI of the client's redirection endpoint (sometimes also called callback URI). */
  redirectUri: string;

  /** The UserInfo endpoint of the authorization server. */
  userInfoEndpoint?: string;

  /**
   * Validates and parses the given JWT.
   *
   * Note that this function is also responsible for validating the JWT's
   * signature
   */
  verifyJwt: (
    jwt: string,
  ) => Promise<JWTVerifyResult>;
}

export class OIDCClient {
  /**
   * Implements the Authorization Code Flow.
   *
   * See {@link https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth OpenID Connect spec, section 3.1.}
   */
  public code: AuthorizationCodeFlow;

  constructor(
    public readonly config: Readonly<OIDCClientConfig>,
  ) {
    this.code = new AuthorizationCodeFlow(this.config);
  }

  async getUserInfo(
    accessToken: string,
    idToken: IDToken,
    options: { requestHeaders?: HeadersInit } = {},
  ) {
    if (typeof this.config.userInfoEndpoint !== "string") {
      throw new UserInfoError(
        "calling getUserInfo() requires a userInfoEndpoint to be configured",
      );
    }
    const requestHeaders = new Headers(options.requestHeaders);
    requestHeaders.set("Authorization", `Bearer ${accessToken}`);
    const response = await fetch(this.config.userInfoEndpoint, {
      headers: requestHeaders,
    });

    if (!response.ok) {
      // TODO: parse error response (https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.5.3.3)
      throw new UserInfoError("userinfo returned an error");
    }

    const userInfoPayload = await this.getUserInfoResponsePayload(
      response.clone(),
    );

    if (
      !includesClaim(
        userInfoPayload,
        "sub",
        (sub): sub is string => sub === idToken.sub,
      )
    ) {
      throw new UserInfoError(
        "the userInfo response body contained an invalid `sub` claim",
      );
    }

    return userInfoPayload;
  }

  protected async getUserInfoResponsePayload(
    response: Response,
  ): Promise<Record<string, unknown>> {
    const contentType = response.headers.get("Content-Type");
    const jsonContentType = "application/json";
    const jwtContentType = "application/jwt";

    switch (contentType) {
      case jsonContentType: {
        let responseBody: unknown;
        try {
          responseBody = await response.json();
        } catch {
          throw new UserInfoError(
            "the userinfo response body was not valid JSON",
          );
        }
        if (!isObject(responseBody)) {
          throw new UserInfoError(
            "the userinfo response body was not a JSON object",
          );
        }
        return responseBody;
      }
      case jwtContentType: {
        let responseBody: string;
        try {
          responseBody = await response.text();
        } catch {
          throw new UserInfoError(`failed to read ${jwtContentType} response`);
        }

        try {
          const { payload } = await this.config.verifyJwt(responseBody);
          return payload;
        } catch {
          throw new UserInfoError(
            `failed to validate the userinfo JWT response`,
          );
        }
      }
      default:
        throw new UserInfoError(
          `the userinfo response had an invalid content-type. Expected ${jsonContentType} or ${jwtContentType}, but got ${contentType}`,
        );
    }
  }
}

/** Thrown when there was an error while requesting data from the UserInfo endpoint */
export class UserInfoError extends Error {
  constructor(message: string) {
    super(message);
  }
}
