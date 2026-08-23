import type { Metadata } from "next";
import "./globals.css";
import { ThemeRegistry } from "@/theme/ThemeRegistry";
import { QueryProvider } from "@/providers/QueryProvider";
import { AuthProvider } from "@/context/AuthContext";
import { AppShell } from "@/components/layout/AppShell";

export const metadata: Metadata = {
  title: "ThreatTrace AI — Cybersecurity Email Investigation Platform",
  description:
    "Production-grade cybersecurity email forensics, AI-driven threat analysis, and tamper-evident SOC investigation platform.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>
        <ThemeRegistry>
          <QueryProvider>
            <AuthProvider>
              <AppShell>{children}</AppShell>
            </AuthProvider>
          </QueryProvider>
        </ThemeRegistry>
      </body>
    </html>
  );
}
