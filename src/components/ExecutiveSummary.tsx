import React from 'react';
import { SecurityAnalysisReport } from '../types/security';
import { 
  CheckCircle2, 
  AlertOctagon, 
  AlertTriangle, 
  Info, 
  Globe, 
  Server, 
  Clock, 
  MapPin, 
  Download, 
  Printer, 
  Share2, 
  RotateCw 
} from 'lucide-react';

interface ExecutiveSummaryProps {
  report: SecurityAnalysisReport;
  onExport: () => void;
  onRescan: () => void;
}

export const ExecutiveSummary: React.FC<ExecutiveSummaryProps> = ({
  report,
  onExport,
  onRescan,
}) => {
  const { summary, hostname, parameters, scanDurationMs } = report;
  const [copiedShare, setCopiedShare] = React.useState(false);

  const handleShare = () => {
    const url = new URL(window.location.href);
    url.searchParams.set('target', hostname);
    navigator.clipboard.writeText(url.toString());
    setCopiedShare(true);
    setTimeout(() => setCopiedShare(false), 2000);
  };

  const handlePrint = () => {
    window.print();
  };

  return (
    <div className="space-y-4 font-serif">
      {/* Top Meta Info Bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-4 rounded-xl bg-slate-900 border border-slate-800 shadow-md">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-slate-800 border border-slate-700 flex items-center justify-center shrink-0">
            <Globe className="w-5 h-5 text-slate-300" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-lg font-bold text-white tracking-tight">{hostname}</h2>
              <span className="text-xs font-mono text-slate-300 px-2 py-0.5 rounded bg-slate-800 border border-slate-700">
                {parameters.infrastructure.httpVersion || 'HTTP/2'}
              </span>
            </div>
            <div className="flex items-center gap-3 text-xs text-slate-400 mt-1 flex-wrap">
              {parameters.infrastructure.ipAddress && (
                <span className="flex items-center gap-1 font-mono">
                  <Server className="w-3.5 h-3.5 text-slate-500" />
                  {parameters.infrastructure.ipAddress}
                </span>
              )}
              {parameters.infrastructure.country && (
                <span className="flex items-center gap-1">
                  <MapPin className="w-3.5 h-3.5 text-slate-500" />
                  {parameters.infrastructure.city ? `${parameters.infrastructure.city}, ` : ''}
                  {parameters.infrastructure.country}
                </span>
              )}
              {parameters.infrastructure.asnOrg && (
                <span className="text-slate-400">
                  ASN: {parameters.infrastructure.asnOrg}
                </span>
              )}
              <span className="flex items-center gap-1 font-mono text-slate-400">
                <Clock className="w-3.5 h-3.5 text-slate-500" />
                {scanDurationMs}ms
              </span>
            </div>
          </div>
        </div>

        {/* Quick Audit Actions */}
        <div className="flex items-center gap-2 shrink-0 self-end md:self-auto">
          <button
            onClick={handleShare}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-300 bg-slate-800 hover:bg-slate-700 hover:text-white rounded-lg transition-colors border border-slate-700"
            title="Copy shareable audit link"
          >
            <Share2 className="w-3.5 h-3.5 text-slate-400" />
            <span>{copiedShare ? 'Copied Link!' : 'Share'}</span>
          </button>

          <button
            onClick={handlePrint}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-300 bg-slate-800 hover:bg-slate-700 hover:text-white rounded-lg transition-colors border border-slate-700"
            title="Print or Save as PDF"
          >
            <Printer className="w-3.5 h-3.5 text-slate-400" />
            <span>Print / PDF</span>
          </button>

          <button
            onClick={onExport}
            className="flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-bold text-slate-950 bg-white hover:bg-slate-200 rounded-lg transition-colors shadow-xs"
          >
            <Download className="w-3.5 h-3.5 text-slate-950" />
            <span>Export Report</span>
          </button>

          <button
            onClick={onRescan}
            className="p-1.5 text-slate-400 hover:text-white hover:bg-slate-800 rounded-lg transition-colors border border-slate-700"
            title="Re-run live audit"
          >
            <RotateCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* 4 Key KPI Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Passed Checks */}
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
            <span className="font-medium">Passed Checks</span>
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-emerald-400 tabular-nums">
            {summary.passedCount}
          </div>
          <p className="text-[11px] text-slate-500 mt-1">Verified security perimeters</p>
        </div>

        {/* Critical Risks */}
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
            <span className="font-medium">Critical Risks</span>
            <AlertOctagon className={`w-4 h-4 ${summary.criticalCount > 0 ? 'text-rose-400' : 'text-slate-600'}`} />
          </div>
          <div className={`text-2xl font-bold font-mono tabular-nums ${summary.criticalCount > 0 ? 'text-rose-400' : 'text-slate-300'}`}>
            {summary.criticalCount}
          </div>
          <p className="text-[11px] text-slate-500 mt-1">Immediate remediation needed</p>
        </div>

        {/* High Warnings */}
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
            <span className="font-medium">High Priority</span>
            <AlertTriangle className={`w-4 h-4 ${summary.highCount > 0 ? 'text-amber-400' : 'text-slate-600'}`} />
          </div>
          <div className={`text-2xl font-bold font-mono tabular-nums ${summary.highCount > 0 ? 'text-amber-400' : 'text-slate-300'}`}>
            {summary.highCount}
          </div>
          <p className="text-[11px] text-slate-500 mt-1">Defense-in-depth gaps</p>
        </div>

        {/* Medium/Low */}
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
            <span className="font-medium">Hardening Notices</span>
            <Info className="w-4 h-4 text-sky-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-slate-200 tabular-nums">
            {summary.mediumCount + summary.lowCount}
          </div>
          <p className="text-[11px] text-slate-500 mt-1">Best-practice improvements</p>
        </div>
      </div>

      {/* Executive Statement Callout */}
      <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
        <div className="text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1">
          Executive Security Assessment
        </div>
        <p className="text-sm text-slate-300 leading-relaxed">
          {summary.executiveStatement}
        </p>
      </div>
    </div>
  );
};
