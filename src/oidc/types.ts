import { Tokens } from "../types.ts";

export interface IDToken {
  iss: string;
  sub: string;
  aud: string | string[];
  exp: number;
  iat: number;
  auth_time?: number;
  nonce?: string;
  acr?: string;
  amr?: string[];
  azp?: string;
  [claimName: string]: unknown;
}

export interface OIDCTokens extends Tokens {
  idTokenString: string;
  idToken: IDToken;
}

export interface JWTPayload {
  iss?: string;
  sub?: string;
  aud?: string | string[];
  jti?: string;
  nbf?: number;
  exp?: number;
  iat?: number;
  [propName: string]: unknown;
}

export interface JWTHeaderParameters {
  alg: string;
}

export interface JWTVerifyResult {
  payload: JWTPayload;
  protectedHeader: JWTHeaderParameters;
}
