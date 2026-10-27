import React, { useState } from 'react';
import { SecurityAnalysisReport } from '../types/security';
import { ArrowRightLeft, Loader2, X } from 'lucide-react';

interface CompareDomainsModalProps {
  currentReport?: SecurityAnalysisReport | null;
  onAnalyze: (url: string) => Promise<SecurityAnalysisReport | null>;
  onClose: () => void;
}

export const CompareDomainsModal: React.FC<CompareDomainsModalProps> = ({
  currentReport,
  onAnalyze,
  onClose,
}) => {
  const [domainA, setDomainA] = useState(currentReport?.hostname || 'github.com');
  const [domainB, setDomainB] = useState('httpbin.org');
  const [reportA, setReportA] = useState<SecurityAnalysisReport | null>(currentReport || null);
  const [reportB, setReportB] = useState<SecurityAnalysisReport | null>(null);
  const [loadingA, setLoadingA] = useState(false);
  const [loadingB, setLoadingB] = useState(false);

  const fetchA = async () => {
    if (!domainA.trim()) return;
    setLoadingA(true);
    const rep = await onAnalyze(domainA);
    setReportA(rep);
    setLoadingA(false);
  };

  const fetchB = async () => {
    if (!domainB.trim()) return;
    setLoadingB(true);
    const rep = await onAnalyze(domainB);
    setReportB(rep);
    setLoadingB(false);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/85 backdrop-blur-xs font-serif">
      <div className="w-full max-w-5xl max-h-[92vh] bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl flex flex-col overflow-hidden">
        {/* Header */}
        <div className="p-4 sm:px-6 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-slate-800 border border-slate-700 flex items-center justify-center">
              <ArrowRightLeft className="w-4 h-4 text-slate-300" />
            </div>
            <div>
              <h3 className="text-base font-bold text-white font-serif">Compare Domain Security Postures</h3>
              <p className="text-xs text-slate-400 font-serif">Benchmark two URLs side-by-side across encryption, headers, and DNS</p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Inputs */}
        <div className="p-4 sm:px-6 border-b border-slate-800 grid grid-cols-1 md:grid-cols-2 gap-4 bg-slate-950">
          <div className="flex items-center gap-2">
            <input
              type="text"
              value={domainA}
              onChange={(e) => setDomainA(e.target.value)}
              placeholder="Domain A (e.g. cloudflare.com)"
              className="flex-1 px-3 py-2 text-xs font-serif bg-slate-900 border border-slate-700 rounded-lg text-white focus:outline-none focus:border-slate-500"
            />
            <button
              onClick={fetchA}
              disabled={loadingA || !domainA.trim()}
              className="px-3.5 py-2 text-xs font-serif font-bold text-slate-950 bg-white hover:bg-slate-200 disabled:opacity-50 rounded-lg transition-colors shrink-0 shadow-xs"
            >
              {loadingA ? <Loader2 className="w-4 h-4 animate-spin text-slate-950" /> : 'Audit A'}
            </button>
          </div>

          <div className="flex items-center gap-2">
            <input
              type="text"
              value={domainB}
              onChange={(e) => setDomainB(e.target.value)}
              placeholder="Domain B (e.g. httpbin.org)"
              className="flex-1 px-3 py-2 text-xs font-serif bg-slate-900 border border-slate-700 rounded-lg text-white focus:outline-none focus:border-slate-500"
            />
            <button
              onClick={fetchB}
              disabled={loadingB || !domainB.trim()}
              className="px-3.5 py-2 text-xs font-serif font-bold text-slate-950 bg-white hover:bg-slate-200 disabled:opacity-50 rounded-lg transition-colors shrink-0 shadow-xs"
            >
              {loadingB ? <Loader2 className="w-4 h-4 animate-spin text-slate-950" /> : 'Audit B'}
            </button>
          </div>
        </div>

        {/* Comparison Tables */}
        <div className="flex-1 overflow-y-auto p-4 sm:p-6 space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Column A */}
            <div className="space-y-4">
              <div className="flex items-center justify-between pb-2 border-b border-slate-800">
                <span className="text-sm font-bold text-white font-mono">{reportA?.hostname || domainA}</span>
                {reportA && (
                  <span className="text-xl font-serif font-extrabold text-white">
                    Grade {reportA.scores.grade} ({reportA.scores.overallScore})
                  </span>
                )}
              </div>

              {reportA ? (
                <div className="space-y-3 text-xs">
                  <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
                    <span className="text-slate-400 font-serif font-medium">SSL / TLS Certificate</span>
                    <div className="text-white font-mono font-semibold">{reportA.parameters.ssl.status.toUpperCase()} ({reportA.parameters.ssl.daysRemaining} days remaining)</div>
                    <div className="text-slate-500 text-[11px] font-serif">{reportA.parameters.ssl.protocolVersion} · {reportA.parameters.ssl.issuer.organization || 'WebTrust'}</div>
                  </div>

                  <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1.5">
                    <span className="text-slate-400 font-serif font-medium">Defensive Headers</span>
                    {reportA.parameters.headers.map((h) => (
                      <div key={h.name} className="flex items-center justify-between font-mono">
                        <span className="text-slate-300 truncate max-w-[180px]">{h.name}</span>
                        <span className={`font-semibold ${h.present ? 'text-emerald-400' : 'text-rose-400'}`}>
                          {h.present ? 'YES' : 'NO'}
                        </span>
                      </div>
                    ))}
                  </div>

                  <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
                    <span className="text-slate-400 font-serif font-medium">Email Authentication</span>
                    <div className="flex justify-between font-mono">
                      <span>SPF: {reportA.parameters.emailSecurity.hasSpf ? 'Active' : 'Missing'}</span>
                      <span>DMARC: {reportA.parameters.emailSecurity.dmarcPolicy}</span>
                    </div>
                  </div>

                  <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
                    <span className="text-slate-400 font-serif font-medium">SQL Injection & Query Defense</span>
                    <div className="flex justify-between font-mono">
                      <span>Score: {reportA.scores.sqliScore ?? 100}%</span>
                      <span className={reportA.parameters.sqli?.wafDetected ? 'text-emerald-400' : 'text-slate-400'}>
                        {reportA.parameters.sqli?.wafDetected ? (reportA.parameters.sqli?.wafProvider || 'WAF Active') : 'No WAF'}
                      </span>
                    </div>
                    <div className="text-[11px] text-slate-500 font-serif">
                      {reportA.parameters.sqli?.dbErrorDisclosureDetected ? 'Critical: DB Errors Leaked' : 'No DB Error Leaks'} · {reportA.parameters.sqli?.parametersDetected.length ?? 0} parameter(s)
                    </div>
                  </div>
                </div>
              ) : (
                <div className="p-8 text-center text-slate-500 bg-slate-950 rounded-xl border border-slate-800 font-serif">
                  Click "Audit A" to load security posture
                </div>
              )}
            </div>

            {/* Column B */}
            <div className="space-y-4">
              <div className="flex items-center justify-between pb-2 border-b border-slate-800">
                <span className="text-sm font-bold text-white font-mono">{reportB?.hostname || domainB}</span>
                {reportB && (
                  <span className="text-xl font-serif font-extrabold text-white">
                    Grade {reportB.scores.grade} ({reportB.scores.overallScore})
                  </span>
                )}
              </div>

              {reportB ? (
                <div className="space-y-3 text-xs">
                  <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
                    <span className="text-slate-400 font-serif font-medium">SSL / TLS Certificate</span>
                    <div className="text-white font-mono font-semibold">{reportB.parameters.ssl.status.toUpperCase()} ({reportB.parameters.ssl.daysRemaining} days remaining)</div>
                    <div className="text-slate-500 text-[11px] font-serif">{reportB.parameters.ssl.protocolVersion} · {reportB.parameters.ssl.issuer.organization || 'WebTrust'}</div>
                  </div>

                  <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1.5">
                    <span className="text-slate-400 font-serif font-medium">Defensive Headers</span>
                    {reportB.parameters.headers.map((h) => (
                      <div key={h.name} className="flex items-center justify-between font-mono">
                        <span className="text-slate-300 truncate max-w-[180px]">{h.name}</span>
                        <span className={`font-semibold ${h.present ? 'text-emerald-400' : 'text-rose-400'}`}>
                          {h.present ? 'YES' : 'NO'}
                        </span>
                      </div>
                    ))}
                  </div>

                  <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
                    <span className="text-slate-400 font-serif font-medium">Email Authentication</span>
                    <div className="flex justify-between font-mono">
                      <span>SPF: {reportB.parameters.emailSecurity.hasSpf ? 'Active' : 'Missing'}</span>
                      <span>DMARC: {reportB.parameters.emailSecurity.dmarcPolicy}</span>
                    </div>
                  </div>

                  <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
                    <span className="text-slate-400 font-serif font-medium">SQL Injection & Query Defense</span>
                    <div className="flex justify-between font-mono">
                      <span>Score: {reportB.scores.sqliScore ?? 100}%</span>
                      <span className={reportB.parameters.sqli?.wafDetected ? 'text-emerald-400' : 'text-slate-400'}>
                        {reportB.parameters.sqli?.wafDetected ? (reportB.parameters.sqli?.wafProvider || 'WAF Active') : 'No WAF'}
                      </span>
                    </div>
                    <div className="text-[11px] text-slate-500 font-serif">
                      {reportB.parameters.sqli?.dbErrorDisclosureDetected ? 'Critical: DB Errors Leaked' : 'No DB Error Leaks'} · {reportB.parameters.sqli?.parametersDetected.length ?? 0} parameter(s)
                    </div>
                  </div>
                </div>
              ) : (
                <div className="p-8 text-center text-slate-500 bg-slate-950 rounded-xl border border-slate-800 font-serif">
                  Click "Audit B" to load benchmark comparison
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
