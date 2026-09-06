"use client";

import React from "react";
import { Header } from "./Header";
import { Footer } from "./Footer";

interface AppShellProps {
  children: React.ReactNode;
}

export const AppShell: React.FC<AppShellProps> = ({ children }) => {
  return (
    <div className="flex flex-col min-h-screen bg-bg-page">
      <Header />
      <main className="flex-1 w-full max-w-[1600px] mx-auto p-4 sm:p-6 md:p-8" role="main">
        {children}
      </main>
      <Footer />
    </div>
  );
};

