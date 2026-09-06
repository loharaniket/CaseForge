import React from "react";
import { Link, useLocation } from "react-router-dom";
import { Shield, UserCheck, LogOut, LogIn, UploadCloud, History } from "lucide-react";
import { useAuth } from "@/context/AuthContext";

export const Header: React.FC = () => {
  const { user, isAuthenticated, logout } = useAuth();
  const location = useLocation();
  const pathname = location.pathname;

  // Basic logic to determine header title based on route
  const getPageTitle = () => {
    if (pathname?.includes("/investigation/")) return "Case Investigation";
    if (pathname === "/investigations") return "Case Registry";
    if (pathname === "/new-investigation") return "New Ingestion";
    if (pathname === "/login") return "Authentication";
    return "Forensic Workspace";
  };

  const isInvestigationsActive = pathname === "/investigations";
  const isNewInvestigationActive = pathname === "/new-investigation" || pathname === "/";

  return (
    <header className="h-16 bg-nav-bg border-b border-[#334E68] flex items-center shrink-0 z-50">
      <div className="w-full flex justify-between items-center px-4 lg:px-6">
        <div className="flex items-center gap-3">
          <Link to="/" className="flex items-center gap-3 no-underline">
            <Shield className="w-6 h-6 text-info" />
            <div className="flex flex-col">
              <h1 className="text-[15px] font-[750] text-white leading-tight tracking-wide">CaseForge</h1>
              <p className="text-[11px] font-[600] text-[#9FB3C8] uppercase tracking-wider">Enterprise SOC Platform</p>
            </div>
          </Link>
          
          <div className="hidden md:flex ml-4 pl-4 border-l border-[#334E68] h-7 items-center text-xs font-semibold text-[#9FB3C8]">
            {getPageTitle()}
          </div>

          <nav className="flex items-center gap-2 ml-4">
            <Link
              to="/investigations"
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors no-underline ${
                isInvestigationsActive
                  ? "bg-[#243B53] text-white border border-[#334E68]"
                  : "text-[#9FB3C8] hover:text-white hover:bg-[#243B53]"
              }`}
            >
              <History className="w-3.5 h-3.5 text-primary" />
              <span>Investigations</span>
            </Link>
            <Link
              to="/new-investigation"
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-bold transition-colors shadow-sm no-underline ${
                isNewInvestigationActive
                  ? "bg-primary text-white ring-2 ring-primary/30"
                  : "bg-primary/90 text-white hover:bg-primary"
              }`}
            >
              <UploadCloud className="w-3.5 h-3.5" />
              <span>New Investigation</span>
            </Link>
          </nav>
        </div>

        <div className="flex items-center gap-4">
          {isAuthenticated && user ? (
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-3 bg-[#243B53] px-3 py-1.5 rounded-[6px] border border-[#334E68]">
                <UserCheck className="w-4 h-4 text-[#9FB3C8]" />
                <div className="flex flex-col">
                  <span className="text-xs font-semibold text-white leading-tight">{user.full_name}</span>
                  <span className="text-[10px] text-[#9FB3C8] uppercase">{user.role}</span>
                </div>
              </div>
              
              <button
                onClick={logout}
                className="flex items-center gap-2 text-xs font-semibold text-[#9FB3C8] hover:text-white transition-colors px-2 py-1.5"
                title="Disconnect from SOC Console"
              >
                <LogOut className="w-4 h-4" />
                <span className="hidden sm:inline">Logout</span>
              </button>
            </div>
          ) : (
            <Link
              to="/login"
              className="flex items-center gap-2 text-xs font-semibold text-[#9FB3C8] hover:text-white bg-[#243B53] hover:bg-[#334E68] px-3 py-2 rounded-[6px] transition-colors"
            >
              <LogIn className="w-4 h-4" />
              <span>Analyst Login</span>
            </Link>
          )}
        </div>
      </div>
    </header>
  );
};
