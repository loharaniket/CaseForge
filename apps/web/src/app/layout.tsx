import type { Metadata } from "next";
import "./globals.css";
import { QueryProvider } from "@/providers/QueryProvider";
import { Header } from "@/components/common/Header";
import { Footer } from "@/components/common/Footer";

export const metadata: Metadata = {
  title: "ThreatTrace AI — Cybersecurity Email Investigation Platform",
  description: "Advanced AI-powered cybersecurity email forensics and SOC investigation platform.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>
        <QueryProvider>
          <Header />
          <main className="main-content">{children}</main>
          <Footer />
        </QueryProvider>
      </body>
    </html>
  );
}
