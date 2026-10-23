"use client";

import { Suspense, useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";

const STORAGE_KEY = "se_oauth_pkce";

type StoredPkce = {
  state: string;
  verifier: string;
  redirectUri: string;
  clientId: string;
};

type TokenResponse = {
  access_token: string;
  id_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
  scope: string;
};

function CallbackInner() {
  const params = useSearchParams();
  const [status, setStatus] = useState("Exchanging authorization code…");
  const [error, setError] = useState<string | null>(null);
  const [tokens, setTokens] = useState<TokenResponse | null>(null);

  useEffect(() => {
    let cancelled = false;

    async function run() {
      const code = params.get("code");
      const state = params.get("state");
      const oauthError = params.get("error");

      if (oauthError) {
        setError(params.get("error_description") || oauthError);
        return;
      }
      if (!code) {
        setError("Missing authorization code");
        return;
      }

      let stored: StoredPkce | null = null;
      try {
        stored = JSON.parse(sessionStorage.getItem(STORAGE_KEY) || "null");
      } catch {
        stored = null;
      }

      if (!stored?.verifier) {
        setError("Missing PKCE verifier — start login again from the home page");
        return;
      }
      if (state && stored.state && state !== stored.state) {
        setError("State mismatch — possible CSRF; restart login");
        return;
      }

      const base =
        process.env.NEXT_PUBLIC_MOCK_IDP_URL || `${window.location.origin}/api/mock-idp`;

      setStatus("POST /token …");
      const res = await fetch(`${base}/token`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          grant_type: "authorization_code",
          code,
          redirect_uri: stored.redirectUri,
          client_id: stored.clientId,
          code_verifier: stored.verifier,
        }),
      });

      const data = await res.json();
      if (!res.ok) {
        setError(data.error_description || data.error || "Token exchange failed");
        return;
      }

      if (cancelled) return;

      const bundle = data as TokenResponse;
      setTokens(bundle);

      try {
        const payload = JSON.parse(
          atob(bundle.access_token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/"))
        );
        localStorage.setItem("se_at", bundle.access_token);
        localStorage.setItem("se_rt", bundle.refresh_token);
        localStorage.setItem("se_id", bundle.id_token);
        localStorage.setItem("se_exp", String((payload.exp || 0) * 1000));
        localStorage.setItem("se_name", payload.name || "Member");
        localStorage.setItem("se_email", payload.email || "");
        sessionStorage.removeItem(STORAGE_KEY);
      } catch {
        /* ignore storage errors */
      }

      console.group("[OAuth2/PKCE] Token response");
      console.log(bundle);
      console.groupEnd();

      setStatus("Tokens stored. Redirecting…");
      setTimeout(() => {
        window.location.href = "/home.html?authed=1";
      }, 900);
    }

    run().catch((e) => setError(e instanceof Error ? e.message : String(e)));
    return () => {
      cancelled = true;
    };
  }, [params]);

  return (
    <main
      style={{
        minHeight: "100vh",
        display: "grid",
        placeItems: "center",
        padding: 24,
        background: "#F272A8",
        color: "#2D1B3D",
      }}
    >
      <div
        style={{
          background: "#fff",
          borderRadius: 16,
          padding: "28px 32px",
          maxWidth: 560,
          width: "100%",
          boxShadow: "0 12px 40px rgba(45,27,61,.2)",
        }}
      >
        <h1 style={{ margin: "0 0 8px", fontSize: 22 }}>Auth callback</h1>
        {error ? (
          <p style={{ color: "#B00040", margin: 0 }}>{error}</p>
        ) : (
          <p style={{ margin: 0, opacity: 0.8 }}>{status}</p>
        )}
        {tokens && (
          <pre
            style={{
              marginTop: 16,
              padding: 12,
              background: "#1A0F25",
              color: "#A0FFB0",
              borderRadius: 8,
              fontSize: 11,
              overflow: "auto",
              maxHeight: 220,
            }}
          >
            {JSON.stringify(
              {
                access_token: tokens.access_token.slice(0, 48) + "…",
                id_token: tokens.id_token.slice(0, 48) + "…",
                refresh_token: tokens.refresh_token.slice(0, 24) + "…",
                token_type: tokens.token_type,
                expires_in: tokens.expires_in,
                scope: tokens.scope,
              },
              null,
              2
            )}
          </pre>
        )}
      </div>
    </main>
  );
}

export default function AuthCallbackPage() {
  return (
    <Suspense fallback={<p style={{ padding: 24 }}>Loading callback…</p>}>
      <CallbackInner />
    </Suspense>
  );
}
