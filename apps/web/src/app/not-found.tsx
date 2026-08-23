import Link from "next/link";
import { ShieldX, Home } from "lucide-react";

export default function NotFound() {
  return (
    <div className="not-found-container">
      <div className="not-found-box">
        <div className="w-12 h-12 rounded-full bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center">
          <ShieldX className="w-6 h-6 text-cyan-400" />
        </div>
        <div>
          <h2 className="text-xl font-bold text-white mb-1">404 — Investigation Vector Not Found</h2>
          <p className="text-sm text-gray-400">
            The requested SOC console route or forensic resource does not exist.
          </p>
        </div>
        <Link href="/" className="action-btn">
          <Home className="w-4 h-4" />
          <span>Return to SOC Overview</span>
        </Link>
      </div>
    </div>
  );
}
