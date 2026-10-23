import { NextRequest, NextResponse } from "next/server";
import {
  capitalizeName,
  issueAuthCode,
  randomId,
} from "@/lib/mock-idp";

export const runtime = "nodejs";

/**
 * Mock IdP — Authorization endpoint (Authorization Code + PKCE).
 * GET /api/mock-idp/authorize?... → 302 redirect_uri?code=...&state=...
 */
export async function GET(req: NextRequest) {
  try {
    const url = req.nextUrl;
    const clientId = url.searchParams.get("client_id") || "sexual_ed_client_001";
    const redirectUri = url.searchParams.get("redirect_uri");
    const state = url.searchParams.get("state") || "";
    const scope =
      url.searchParams.get("scope") || "openid profile email events:write";
    const codeChallenge = url.searchParams.get("code_challenge");
    const codeChallengeMethod =
      url.searchParams.get("code_challenge_method") || "S256";
    const responseType = url.searchParams.get("response_type") || "code";
    const loginHint =
      url.searchParams.get("login_hint") ||
      url.searchParams.get("email") ||
      `user_${randomId(3)}@mock-idp.test`;

    if (responseType !== "code") {
      return NextResponse.json(
        { error: "unsupported_response_type" },
        { status: 400 }
      );
    }
    if (!redirectUri) {
      return NextResponse.json(
        { error: "invalid_request", error_description: "redirect_uri required" },
        { status: 400 }
      );
    }
    if (!codeChallenge || codeChallengeMethod !== "S256") {
      return NextResponse.json(
        {
          error: "invalid_request",
          error_description: "PKCE S256 code_challenge required",
        },
        { status: 400 }
      );
    }

    const email = loginHint;
    const name = capitalizeName(email);
    const sub = `usr_${randomId(6)}`;

    const code = issueAuthCode({
      client_id: clientId,
      redirect_uri: redirectUri,
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
      scope,
      email,
      name,
      sub,
    });

    const dest = new URL(redirectUri, req.url);
    dest.searchParams.set("code", code);
    if (state) dest.searchParams.set("state", state);

    return NextResponse.redirect(dest, 302);
  } catch (err) {
    const message = err instanceof Error ? err.message : "authorize_failed";
    return NextResponse.json(
      { error: "server_error", error_description: message },
      { status: 500 }
    );
  }
}
