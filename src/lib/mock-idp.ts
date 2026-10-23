import crypto from "crypto";
import jwt from "jsonwebtoken";

const ISSUER = "https://mock-idp.local";
const DEFAULT_CLIENT_ID = "sexual_ed_client_001";
const CODE_TTL_SEC = 5 * 60;
const ACCESS_TTL_SEC = 3600;

export type AuthCodeClaims = {
  typ: "auth_code";
  client_id: string;
  redirect_uri: string;
  code_challenge: string;
  code_challenge_method: "S256";
  scope: string;
  email: string;
  name: string;
  sub: string;
};

export type TokenBundle = {
  access_token: string;
  id_token: string;
  refresh_token: string;
  token_type: "Bearer";
  expires_in: number;
  scope: string;
};

function getSecret(): string {
  const secret = process.env.JWT_SECRET;
  if (!secret) {
    throw new Error("JWT_SECRET is not set");
  }
  return secret;
}

export function randomId(bytes = 16): string {
  return crypto.randomBytes(bytes).toString("hex");
}

export function capitalizeName(email: string): string {
  const local = email.split("@")[0] ?? "user";
  return local
    .replace(/[_.\-]+/g, " ")
    .split(" ")
    .filter(Boolean)
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ");
}

export function issueAuthCode(claims: Omit<AuthCodeClaims, "typ">): string {
  return jwt.sign({ typ: "auth_code", ...claims }, getSecret(), {
    expiresIn: CODE_TTL_SEC,
    issuer: ISSUER,
  });
}

export function verifyAuthCode(code: string): AuthCodeClaims {
  const decoded = jwt.verify(code, getSecret(), { issuer: ISSUER });
  if (typeof decoded === "string" || decoded.typ !== "auth_code") {
    throw new Error("Invalid authorization code");
  }
  return decoded as AuthCodeClaims;
}

export function verifyPkceS256(verifier: string, challenge: string): boolean {
  const digest = crypto.createHash("sha256").update(verifier).digest();
  const computed = digest
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
  return computed === challenge;
}

export function issueTokenBundle(input: {
  sub: string;
  email: string;
  name: string;
  clientId: string;
  scope: string;
}): TokenBundle {
  const now = Math.floor(Date.now() / 1000);
  const secret = getSecret();
  const clientId = input.clientId || DEFAULT_CLIENT_ID;

  const accessPayload = {
    iss: ISSUER,
    sub: input.sub,
    aud: clientId,
    email: input.email,
    name: input.name,
    scope: input.scope,
    iat: now,
    exp: now + ACCESS_TTL_SEC,
    jti: randomId(8),
  };

  const idPayload = {
    ...accessPayload,
    nonce: randomId(8),
    auth_time: now,
  };

  const access_token = jwt.sign(accessPayload, secret);
  const id_token = jwt.sign(idPayload, secret);
  const refresh_token = jwt.sign(
    {
      typ: "refresh",
      sub: input.sub,
      email: input.email,
      name: input.name,
      client_id: clientId,
      scope: input.scope,
      iat: now,
      exp: now + 60 * 60 * 24 * 30,
    },
    secret
  );

  return {
    access_token,
    id_token,
    refresh_token,
    token_type: "Bearer",
    expires_in: ACCESS_TTL_SEC,
    scope: input.scope,
  };
}

export { DEFAULT_CLIENT_ID, ISSUER };
