import React, { useState, useEffect } from 'react';
import { UrlInputBar } from './components/UrlInputBar';
import { ScoreGauge } from './components/ScoreGauge';
import { ExecutiveSummary } from './components/ExecutiveSummary';
import { FindingsList } from './components/FindingsList';
import { SslCertViewer } from './components/SslCertViewer';
import { SecurityHeadersViewer } from './components/SecurityHeadersViewer';
import { DnsEmailViewer } from './components/DnsEmailViewer';
import { CookieAuditViewer } from './components/CookieAuditViewer';
import { InfrastructureViewer } from './components/InfrastructureViewer';
import { ThreatHeuristicsViewer } from './components/ThreatHeuristicsViewer';
import { SqliAuditViewer } from './components/SqliAuditViewer';
import { ReportExportModal } from './components/ReportExportModal';
import { CompareDomainsModal } from './components/CompareDomainsModal';
import { RemediationGuide } from './components/RemediationGuide';
import { BenchmarkTargetsView } from './components/BenchmarkTargetsView';
import { MethodologyView } from './components/MethodologyView';
import { SecurityAnalysisReport } from './types/security';
import { runClientFallbackAnalysis } from './services/clientAnalyzer';
import { 
  ShieldCheck, 
  Lock, 
  Layers, 
  Mail, 
  Cookie, 
  Network, 
  Fingerprint, 
  Database,
  AlertCircle, 
  Loader2 
} from 'lucide-react';

export default function App() {
  const [report, setReport] = useState<SecurityAnalysisReport | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [scanStep, setScanStep] = useState<string>('');
  const [error, setError] = useState<string | null>(null);
  const [activeView, setActiveView] = useState<'scanner' | 'benchmark' | 'remediation' | 'compare' | 'methodology'>('scanner');
  const [activeTab, setActiveTab] = useState<
    'overview' | 'ssl' | 'headers' | 'dns' | 'cookies' | 'sqli' | 'infrastructure' | 'heuristics'
  >('overview');
  const [isExportOpen, setIsExportOpen] = useState<boolean>(false);

  const handleAnalyze = async (urlToAnalyze: string): Promise<SecurityAnalysisReport | null> => {
    setIsLoading(true);
    setError(null);
    setScanStep('Resolving DNS records (A, AAAA, MX, TXT, CAA)...');

    const steps = [
      'Resolving DNS records (A, AAAA, MX, TXT, CAA)...',
      'Establishing TLS socket handshake & inspecting X.509 certificate...',
      'Auditing HTTP response security headers (HSTS, CSP, X-Frame-Options)...',
      'Auditing SQL injection defense, query parameters & database error disclosure...',
      'Evaluating email anti-spoofing policies (SPF, DMARC)...',
      'Inspecting cookie privacy attributes and redirect chain...',
    ];

    let stepIndex = 0;
    const interval = setInterval(() => {
      stepIndex = (stepIndex + 1) % steps.length;
      setScanStep(steps[stepIndex]);
    }, 700);

    let reportData: SecurityAnalysisReport | null = null;

    try {
      try {
        const res = await fetch('/api/analyze', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url: urlToAnalyze }),
        });

        if (res.ok) {
          const json = await res.json();
          if (json && !json.error && json.scores) {
            reportData = json;
          }
        }
      } catch (networkErr) {
        console.warn('Backend API unreachable, triggering live client-side DoH security audit:', networkErr);
      }

      // If backend was unreachable or returned an error, invoke resilient live client-side DoH analyzer
      if (!reportData) {
        reportData = await runClientFallbackAnalysis(urlToAnalyze);
      }

      clearInterval(interval);
      setReport(reportData);
      setActiveView('scanner');
      setActiveTab('overview');
      return reportData;
    } catch (err: any) {
      clearInterval(interval);
      setError(err.message || 'An unexpected error occurred while auditing the URL');
      return null;
    } finally {
      setIsLoading(false);
      setScanStep('');
    }
  };

  // Check URL query param on mount (e.g. ?target=...)
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const target = params.get('target');
    if (target) {
      handleAnalyze(target);
    }
  }, []);

  const handleNewScan = () => {
    setReport(null);
    setError(null);
    setActiveView('scanner');
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-serif">
      {/* Main Viewport */}
      <main className="flex-1 flex flex-col justify-center max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* INITIAL STATE: Header contents removed, white text directly on top of scanner bar */}
        {!report && !isLoading && (
          <div className="flex-1 flex flex-col items-center justify-center my-auto py-20 w-full space-y-6">
            <div className="w-full max-w-3xl text-center space-y-4">
              <div className="space-y-2 mb-6">
                <h1 className="text-4xl sm:text-5xl md:text-6xl font-normal text-white tracking-tight font-serif">
                  CyberScan
                </h1>
                <p className="text-base sm:text-lg text-white font-serif tracking-wide">
                  URL &amp; Domain Security Posture Engine
                </p>
                <p className="text-xs sm:text-sm text-slate-300 font-serif">
                  TLS / SSL Certificates · Security Headers · DNS Records · Cookie Security · SQL Injection
                </p>
              </div>

              <UrlInputBar
                onAnalyze={handleAnalyze}
                isLoading={isLoading}
                autoFocus={true}
              />
            </div>

            {error && (
              <div className="w-full max-w-3xl p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 flex items-center gap-2.5 text-rose-300 text-xs font-serif">
                <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
                <span>{error}</span>
              </div>
            )}
          </div>
        )}

        {/* LOADING STATE */}
        {isLoading && (
          <div className="flex-1 flex flex-col items-center justify-center my-auto py-16 space-y-6 w-full">
            <div className="w-full max-w-3xl text-center space-y-4">
              <div className="space-y-2 mb-6">
                <h1 className="text-4xl sm:text-5xl font-normal text-white tracking-tight font-serif">
                  CyberScan
                </h1>
                <p className="text-base text-white font-serif tracking-wide">
                  Analyzing Target Security Posture...
                </p>
              </div>

              <UrlInputBar
                onAnalyze={handleAnalyze}
                isLoading={true}
              />
            </div>

            <div className="p-8 rounded-2xl bg-slate-900 border border-slate-800 text-center space-y-3 max-w-md w-full shadow-lg">
              <div className="w-10 h-10 rounded-xl bg-slate-800 border border-slate-700 flex items-center justify-center mx-auto text-slate-300">
                <Loader2 className="w-5 h-5 animate-spin" />
              </div>
              <div className="space-y-1">
                <h3 className="text-sm font-semibold text-white font-serif">Auditing Target Domain</h3>
                <p className="text-xs font-mono text-slate-400">{scanStep}</p>
              </div>
              <div className="w-40 h-1 bg-slate-800 rounded-full mx-auto overflow-hidden">
                <div className="w-full h-full bg-white rounded-full animate-pulse" />
              </div>
            </div>
          </div>
        )}

        {/* SCANNED STATE: Report is active */}
        {report && !isLoading && (
          <div className="space-y-8">
            {/* Top Scanner Bar with White Title and Clean Actions */}
            <div className="no-print space-y-4 pb-2">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <div>
                  <h1 
                    onClick={handleNewScan}
                    className="text-2xl font-normal text-white tracking-tight font-serif cursor-pointer hover:text-slate-200 transition-colors"
                  >
                    CyberScan
                  </h1>
                  <span className="text-xs text-white/70 font-serif">URL Security Report</span>
                </div>
                <div className="flex items-center gap-3">
                  <button
                    onClick={() => setIsExportOpen(true)}
                    className="inline-flex items-center gap-2 px-3 py-1.5 text-xs font-serif text-slate-300 bg-slate-900 border border-slate-700 rounded-lg hover:bg-slate-800 hover:text-white transition-colors"
                  >
                    Export Report
                  </button>
                  <button
                    onClick={handleNewScan}
                    className="inline-flex items-center justify-center px-4 py-1.5 text-xs font-serif font-bold text-slate-950 bg-white hover:bg-slate-200 rounded-lg shadow-xs transition-colors"
                  >
                    New Scan
                  </button>
                </div>
              </div>

              <UrlInputBar
                onAnalyze={handleAnalyze}
                isLoading={isLoading}
                initialUrl={report.hostname}
              />
            </div>

            {error && (
              <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 flex items-center justify-between gap-3 text-rose-300 text-xs font-serif">
                <div className="flex items-center gap-2">
                  <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
                  <span>{error}</span>
                </div>
              </div>
            )}

            {activeView === 'scanner' && (
              <div className="space-y-8">
                {/* Executive Summary Card */}
                <ExecutiveSummary
                  report={report}
                  onExport={() => setIsExportOpen(true)}
                  onRescan={() => handleAnalyze(report.targetUrl)}
                />

                {/* Overall Score Gauge & 5-Pillar Breakdown */}
                <ScoreGauge scores={report.scores} />

                {/* Deep-Dive Inspection Tabs */}
                <div className="space-y-4">
                  <div className="flex items-center gap-1.5 p-1 bg-slate-900 border border-slate-800 rounded-xl overflow-x-auto no-print">
                    <button
                      onClick={() => setActiveTab('overview')}
                      className={`px-3.5 py-2 text-xs font-serif font-medium rounded-lg whitespace-nowrap transition-colors flex items-center gap-2 ${
                        activeTab === 'overview'
                          ? 'bg-slate-800 text-white shadow-xs font-bold'
                          : 'text-slate-400 hover:text-white'
                      }`}
                    >
                      <ShieldCheck className="w-4 h-4 text-emerald-400" />
                      <span>Findings & Remediations</span>
                      <span className="font-mono text-[11px] px-1.5 py-0.2 rounded bg-slate-950 text-slate-400">
                        {report.findings.length}
                      </span>
                    </button>

                    <button
                      onClick={() => setActiveTab('ssl')}
                      className={`px-3.5 py-2 text-xs font-serif font-medium rounded-lg whitespace-nowrap transition-colors flex items-center gap-2 ${
                        activeTab === 'ssl'
                          ? 'bg-slate-800 text-white shadow-xs font-bold'
                          : 'text-slate-400 hover:text-white'
                      }`}
                    >
                      <Lock className="w-4 h-4 text-slate-400" />
                      <span>SSL / TLS Certificate</span>
                      <span className="font-mono text-[11px] text-slate-300 font-semibold">
                        {report.parameters.ssl.daysRemaining}d
                      </span>
                    </button>

                    <button
                      onClick={() => setActiveTab('headers')}
                      className={`px-3.5 py-2 text-xs font-serif font-medium rounded-lg whitespace-nowrap transition-colors flex items-center gap-2 ${
                        activeTab === 'headers'
                          ? 'bg-slate-800 text-white shadow-xs font-bold'
                          : 'text-slate-400 hover:text-white'
                      }`}
                    >
                      <Layers className="w-4 h-4 text-slate-400" />
                      <span>Security Headers</span>
                      <span className="font-mono text-[11px] text-slate-400">
                        {report.parameters.headers.filter((h) => h.present).length}/9
                      </span>
                    </button>

                    <button
                      onClick={() => setActiveTab('dns')}
                      className={`px-3.5 py-2 text-xs font-serif font-medium rounded-lg whitespace-nowrap transition-colors flex items-center gap-2 ${
                        activeTab === 'dns'
                          ? 'bg-slate-800 text-white shadow-xs font-bold'
                          : 'text-slate-400 hover:text-white'
                      }`}
                    >
                      <Mail className="w-4 h-4 text-slate-400" />
                      <span>DNS & Email Defense</span>
                    </button>

                    <button
                      onClick={() => setActiveTab('cookies')}
                      className={`px-3.5 py-2 text-xs font-serif font-medium rounded-lg whitespace-nowrap transition-colors flex items-center gap-2 ${
                        activeTab === 'cookies'
                          ? 'bg-slate-800 text-white shadow-xs font-bold'
                          : 'text-slate-400 hover:text-white'
                      }`}
                    >
                      <Cookie className="w-4 h-4 text-slate-400" />
                      <span>Cookie Safety</span>
                      <span className="font-mono text-[11px] text-slate-400">
                        {report.parameters.cookies.length}
                      </span>
                    </button>

                    <button
                      onClick={() => setActiveTab('sqli')}
                      className={`px-3.5 py-2 text-xs font-serif font-medium rounded-lg whitespace-nowrap transition-colors flex items-center gap-2 ${
                        activeTab === 'sqli'
                          ? 'bg-slate-800 text-white shadow-xs font-bold'
                          : 'text-slate-400 hover:text-white'
                      }`}
                    >
                      <Database className="w-4 h-4 text-slate-400" />
                      <span>SQL Injection & Query Defense</span>
                      <span className="font-mono text-[11px] text-slate-400">
                        {report.parameters.sqli.parametersDetected.length}
                      </span>
                    </button>

                    <button
                      onClick={() => setActiveTab('infrastructure')}
                      className={`px-3.5 py-2 text-xs font-serif font-medium rounded-lg whitespace-nowrap transition-colors flex items-center gap-2 ${
                        activeTab === 'infrastructure'
                          ? 'bg-slate-800 text-white shadow-xs font-bold'
                          : 'text-slate-400 hover:text-white'
                      }`}
                    >
                      <Network className="w-4 h-4 text-slate-400" />
                      <span>Infrastructure & Hops</span>
                      <span className="font-mono text-[11px] text-slate-400">
                        {report.parameters.redirects.totalHops}
                      </span>
                    </button>

                    <button
                      onClick={() => setActiveTab('heuristics')}
                      className={`px-3.5 py-2 text-xs font-serif font-medium rounded-lg whitespace-nowrap transition-colors flex items-center gap-2 ${
                        activeTab === 'heuristics'
                          ? 'bg-slate-800 text-white shadow-xs font-bold'
                          : 'text-slate-400 hover:text-white'
                      }`}
                    >
                      <Fingerprint className="w-4 h-4 text-slate-400" />
                      <span>Threat Heuristics</span>
                    </button>
                  </div>

                  {/* Tab Contents */}
                  <div className="pt-2">
                    {activeTab === 'overview' && <FindingsList findings={report.findings} />}
                    {activeTab === 'ssl' && <SslCertViewer ssl={report.parameters.ssl} hostname={report.hostname} />}
                    {activeTab === 'headers' && <SecurityHeadersViewer headers={report.parameters.headers} />}
                    {activeTab === 'dns' && (
                      <DnsEmailViewer
                        dns={report.parameters.dns}
                        emailSecurity={report.parameters.emailSecurity}
                        hostname={report.hostname}
                      />
                    )}
                    {activeTab === 'cookies' && <CookieAuditViewer cookies={report.parameters.cookies} />}
                    {activeTab === 'sqli' && (
                      <SqliAuditViewer
                        sqli={report.parameters.sqli}
                        targetUrl={report.targetUrl}
                      />
                    )}
                    {activeTab === 'infrastructure' && (
                      <InfrastructureViewer
                        redirects={report.parameters.redirects}
                        infrastructure={report.parameters.infrastructure}
                      />
                    )}
                    {activeTab === 'heuristics' && (
                      <ThreatHeuristicsViewer heuristics={report.parameters.heuristics} />
                    )}
                  </div>
                </div>
              </div>
            )}

            {/* Benchmark Targets View */}
            {activeView === 'benchmark' && (
              <BenchmarkTargetsView
                onSelectDomain={(domain) => {
                  setActiveView('scanner');
                  handleAnalyze(domain);
                }}
              />
            )}

            {/* Hardening Guides View */}
            {activeView === 'remediation' && <RemediationGuide />}

            {/* Technical Methodology View */}
            {activeView === 'methodology' && <MethodologyView />}

            {/* Compare Domains View */}
            {activeView === 'compare' && (
              <CompareDomainsModal
                currentReport={report}
                onAnalyze={handleAnalyze}
                onClose={() => setActiveView('scanner')}
              />
            )}
          </div>
        )}
      </main>

      {/* Report Export Modal */}
      {isExportOpen && report && (
        <ReportExportModal
          report={report}
          onClose={() => setIsExportOpen(false)}
        />
      )}


    </div>
  );
}
