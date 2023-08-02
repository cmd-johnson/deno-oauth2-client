import { OAuth2ClientConfig } from "../oauth2_client.ts";
import { AuthorizationCodeFlow } from "./authorization_code_flow.ts";
import { JWTVerifyResult } from "./types.ts";

export interface OIDCClientConfig extends OAuth2ClientConfig {
  /** The URI of the client's redirection endpoint (sometimes also called callback URI). */
  redirectUri: string;

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
}
