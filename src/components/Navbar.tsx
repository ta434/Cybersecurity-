import React from 'react';
import { ShieldCheck, FileText, ArrowRightLeft, Terminal, Shield, HelpCircle } from 'lucide-react';

interface NavbarProps {
  activeView: 'scanner' | 'benchmark' | 'remediation' | 'compare' | 'methodology';
  setActiveView: (view: 'scanner' | 'benchmark' | 'remediation' | 'compare' | 'methodology') => void;
  onNewScan: () => void;
  hasActiveReport: boolean;
  onOpenExport?: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  activeView,
  setActiveView,
  onNewScan,
  hasActiveReport,
  onOpenExport,
}) => {
  return (
    <header className="sticky top-0 z-40 w-full border-b border-slate-800/80 bg-slate-950/90 backdrop-blur-md">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between gap-8">
        {/* Zone 1: Brand title, single line */}
        <div 
          onClick={onNewScan}
          className="flex items-center gap-2.5 cursor-pointer whitespace-nowrap shrink-0 group"
          role="button"
          tabIndex={0}
          aria-label="CyberScan home"
        >
          <div className="w-8 h-8 rounded-lg bg-slate-800 border border-slate-700 flex items-center justify-center text-white shadow-xs">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-base font-bold tracking-tight text-white font-serif">
              CyberScan
            </span>
            <span className="hidden sm:inline-block text-[11px] font-mono text-slate-400 uppercase tracking-wider">
              URL Security
            </span>
          </div>
        </div>

        {/* Zone 2: Nav links */}
        <nav className="flex items-center gap-3 sm:gap-6 text-xs sm:text-sm font-serif overflow-x-auto no-scrollbar">
          <button
            onClick={() => setActiveView('scanner')}
            className={`whitespace-nowrap shrink-0 transition-colors ${
              activeView === 'scanner' ? 'text-white font-bold' : 'text-slate-400 hover:text-white'
            }`}
          >
            Scanner
          </button>

          <button
            onClick={() => setActiveView('compare')}
            className={`whitespace-nowrap shrink-0 transition-colors flex items-center gap-1.5 ${
              activeView === 'compare' ? 'text-white font-bold' : 'text-slate-400 hover:text-white'
            }`}
          >
            <ArrowRightLeft className="w-3.5 h-3.5 text-slate-400" />
            Compare
          </button>

          <button
            onClick={() => setActiveView('remediation')}
            className={`whitespace-nowrap shrink-0 transition-colors flex items-center gap-1.5 ${
              activeView === 'remediation' ? 'text-white font-bold' : 'text-slate-400 hover:text-white'
            }`}
          >
            <Terminal className="w-3.5 h-3.5 text-slate-400" />
            Hardening
          </button>

          <button
            onClick={() => setActiveView('benchmark')}
            className={`whitespace-nowrap shrink-0 transition-colors flex items-center gap-1.5 ${
              activeView === 'benchmark' ? 'text-white font-bold' : 'text-slate-400 hover:text-white'
            }`}
          >
            <Shield className="w-3.5 h-3.5 text-slate-400" />
            Benchmarks
          </button>

          <button
            onClick={() => setActiveView('methodology')}
            className={`whitespace-nowrap shrink-0 transition-colors flex items-center gap-1.5 ${
              activeView === 'methodology' ? 'text-white font-bold' : 'text-slate-400 hover:text-white'
            }`}
          >
            <HelpCircle className="w-3.5 h-3.5 text-slate-400" />
            Data Source
          </button>
        </nav>

        {/* Zone 3: 1 primary action */}
        <div className="flex items-center gap-3 shrink-0">
          {hasActiveReport && onOpenExport && (
            <button
              onClick={onOpenExport}
              className="hidden sm:inline-flex items-center gap-2 px-3 py-1.5 text-xs font-serif font-medium text-slate-300 bg-slate-900 border border-slate-700 rounded-lg hover:bg-slate-800 hover:text-white transition-colors whitespace-nowrap shrink-0"
              title="Export complete security report as PDF, Markdown, or JSON"
            >
              <FileText className="w-3.5 h-3.5 text-slate-400" />
              <span>Export Report</span>
            </button>
          )}

          <button
            onClick={onNewScan}
            className="inline-flex items-center justify-center px-4 py-2 text-xs font-serif font-bold text-slate-950 bg-white hover:bg-slate-200 rounded-lg shadow-xs transition-colors whitespace-nowrap shrink-0"
          >
            New Scan
          </button>
        </div>
      </div>
    </header>
  );
};
