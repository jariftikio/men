import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Sexual_ed — Mock IdP Harness",
  description: "OAuth2 Authorization Code + PKCE test harness",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body style={{ margin: 0, fontFamily: "system-ui, sans-serif" }}>
        {children}
      </body>
    </html>
  );
}
