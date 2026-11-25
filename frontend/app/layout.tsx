import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = { title: "RelayOps · Incident Desk", description: "Incident response and alert management" };

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en"><body>{children}</body></html>;
}
