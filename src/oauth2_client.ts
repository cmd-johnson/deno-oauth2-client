import { AuthorizationCodeGrant } from "./authorization_code_grant.ts";

export interface RequestOptions {
  headers?: Record<string, string>;
  params?: Record<string, string>;
}

export interface OAuth2ClientConfig {
  clientId: string;
  clientSecret?: string;
  authorizationEndpointUri: string;
  redirectUri?: string;
  accessTokenUri: string;
  defaults?: {
    requestOptions?: RequestOptions;
    scope?: string | string[];
    stateValidator?: (state: string | null) => boolean;
  };
}

export class OAuth2Client {
  public code = new AuthorizationCodeGrant(this);

  constructor(
    public readonly config: Readonly<OAuth2ClientConfig>,
  ) {}
}
