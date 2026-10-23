import { NextRequest, NextResponse } from "next/server";
import {
  issueTokenBundle,
  verifyAuthCode,
  verifyPkceS256,
} from "@/lib/mock-idp";

export const runtime = "nodejs";

/**
 * Mock IdP — Token endpoint.
 * POST /api/mock-idp/token
 * Body (JSON or form): grant_type, code, redirect_uri, client_id, code_verifier
 */
export async function POST(req: NextRequest) {
  try {
    const contentType = req.headers.get("content-type") || "";
    let body: Record<string, string> = {};

    if (contentType.includes("application/json")) {
      body = (await req.json()) as Record<string, string>;
    } else {
      const form = await req.formData();
      form.forEach((value, key) => {
        body[key] = String(value);
      });
    }

    const grantType = body.grant_type || "authorization_code";
    const code = body.code;
    const redirectUri = body.redirect_uri;
    const clientId = body.client_id;
    const codeVerifier = body.code_verifier;

    if (grantType !== "authorization_code") {
      return NextResponse.json(
        { error: "unsupported_grant_type" },
        { status: 400 }
      );
    }
    if (!code || !redirectUri || !codeVerifier) {
      return NextResponse.json(
        {
          error: "invalid_request",
          error_description: "code, redirect_uri, and code_verifier required",
        },
        { status: 400 }
      );
    }

    let claims;
    try {
      claims = verifyAuthCode(code);
    } catch {
      return NextResponse.json(
        { error: "invalid_grant", error_description: "Invalid or expired code" },
        { status: 400 }
      );
    }

    if (claims.redirect_uri !== redirectUri) {
      return NextResponse.json(
        {
          error: "invalid_grant",
          error_description: "redirect_uri mismatch",
        },
        { status: 400 }
      );
    }
    if (clientId && claims.client_id !== clientId) {
      return NextResponse.json(
        { error: "invalid_client", error_description: "client_id mismatch" },
        { status: 400 }
      );
    }
    if (!verifyPkceS256(codeVerifier, claims.code_challenge)) {
      return NextResponse.json(
        {
          error: "invalid_grant",
          error_description: "PKCE verification failed",
        },
        { status: 400 }
      );
    }

    const tokens = issueTokenBundle({
      sub: claims.sub,
      email: claims.email,
      name: claims.name,
      clientId: claims.client_id,
      scope: claims.scope,
    });

    return NextResponse.json(tokens, {
      headers: { "Cache-Control": "no-store" },
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : "token_failed";
    return NextResponse.json(
      { error: "server_error", error_description: message },
      { status: 500 }
    );
  }
}
