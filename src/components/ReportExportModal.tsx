import React, { useState } from 'react';
import { SecurityAnalysisReport } from '../types/security';
import { X, Printer, Download, Copy, Check, FileText } from 'lucide-react';

interface ReportExportModalProps {
  report: SecurityAnalysisReport;
  onClose: () => void;
}

export const ReportExportModal: React.FC<ReportExportModalProps> = ({ report, onClose }) => {
  const [activeTab, setActiveTab] = useState<'preview' | 'markdown' | 'json'>('preview');
  const [copied, setCopied] = useState(false);

  // Generate clean Markdown Report
  const generateMarkdown = (): string => {
    return `# Cybersecurity URL Assessment Report
**Target**: ${report.targetUrl}
**Hostname**: ${report.hostname}
**Audit Date**: ${new Date(report.scanTimestamp).toUTCString()}
**Security Grade**: ${report.scores.grade} (${report.scores.overallScore}/100)

---

## Executive Summary
${report.summary.executiveStatement}

- **Critical Vulnerabilities**: ${report.summary.criticalCount}
- **High Priority Risks**: ${report.summary.highCount}
- **Medium Hardening Opportunities**: ${report.summary.mediumCount}
- **Low Severity / Best Practice Notices**: ${report.summary.lowCount}
- **Passed Controls**: ${report.summary.passedCount}

---

## Category Score Breakdown
| Security Perimeter | Score | Weight |
|---|---|---|
| SSL / TLS Encryption | ${report.scores.sslScore}% | 20% |
| HTTP Security Headers | ${report.scores.headersScore}% | 20% |
| SQLi & Query Defense | ${report.scores.sqliScore ?? 100}% | 20% |
| DNS & Email Authentication | ${report.scores.dnsEmailScore}% | 15% |
| Cookie Privacy & Flags | ${report.scores.cookieScore}% | 15% |
| Host & HTTPS Redirects | ${report.scores.infrastructureScore}% | 10% |

---

## Findings & Actionable Remediations

${report.findings
  .map(
    (f, idx) => `### ${idx + 1}. [${f.severity.toUpperCase()}] ${f.title}
- **Category**: ${f.category}
- **Description**: ${f.description}
- **Technical Impact**: ${f.impact}
- **Remediation**: ${f.remediation}
${f.owasp ? `- **OWASP Ref**: ${f.owasp}` : ''}
${f.cwe ? `- **CWE Ref**: ${f.cwe}` : ''}
`
  )
  .join('\n')}

---
*Report generated automatically by CyberScan Security Auditor.*
`;
  };

  const markdownText = generateMarkdown();
  const jsonText = JSON.stringify(report, null, 2);

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownloadFile = (content: string, filename: string, type: string) => {
    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-xs font-serif">
      <div className="w-full max-w-4xl max-h-[90vh] bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl flex flex-col overflow-hidden">
        {/* Modal Header */}
        <div className="p-4 sm:px-6 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-slate-800 border border-slate-700 flex items-center justify-center">
              <FileText className="w-4 h-4 text-slate-300" />
            </div>
            <div>
              <h3 className="text-base font-bold text-white font-serif">Export Security Audit Report</h3>
              <p className="text-xs text-slate-400 font-serif">{report.hostname} · Grade {report.scores.grade}</p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {/* Tab choices */}
            <div className="flex items-center gap-1 p-0.5 bg-slate-950 rounded-lg border border-slate-800">
              <button
                onClick={() => setActiveTab('preview')}
                className={`px-3 py-1 text-xs font-serif font-medium rounded-md transition-colors ${
                  activeTab === 'preview' ? 'bg-slate-800 text-white font-bold' : 'text-slate-400 hover:text-white'
                }`}
              >
                Visual Preview
              </button>
              <button
                onClick={() => setActiveTab('markdown')}
                className={`px-3 py-1 text-xs font-serif font-medium rounded-md transition-colors ${
                  activeTab === 'markdown' ? 'bg-slate-800 text-white font-bold' : 'text-slate-400 hover:text-white'
                }`}
              >
                Markdown
              </button>
              <button
                onClick={() => setActiveTab('json')}
                className={`px-3 py-1 text-xs font-serif font-medium rounded-md transition-colors ${
                  activeTab === 'json' ? 'bg-slate-800 text-white font-bold' : 'text-slate-400 hover:text-white'
                }`}
              >
                JSON
              </button>
            </div>

            <button
              onClick={onClose}
              className="p-1.5 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition-colors ml-2"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Modal Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {activeTab === 'preview' && (
            <div className="space-y-6 print-card p-6 rounded-xl bg-slate-950 border border-slate-800 text-slate-300">
              <div className="border-b border-slate-800 pb-4 flex items-center justify-between">
                <div>
                  <span className="text-xs font-mono uppercase tracking-wider text-slate-400">Formal Audit Report</span>
                  <h2 className="text-xl font-bold text-white mt-0.5 font-serif">{report.hostname}</h2>
                  <span className="text-xs text-slate-400 font-serif">Audited: {new Date(report.scanTimestamp).toLocaleString()}</span>
                </div>
                <div className="text-right">
                  <div className="text-3xl font-extrabold font-serif text-white">{report.scores.grade}</div>
                  <span className="text-xs font-mono text-slate-400">{report.scores.overallScore}/100</span>
                </div>
              </div>

              {/* Statement */}
              <div className="space-y-1">
                <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Executive Summary</span>
                <p className="text-sm text-slate-300 leading-relaxed font-serif">{report.summary.executiveStatement}</p>
              </div>

              {/* Findings count strip */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                  <span className="text-xs text-slate-400 block font-serif">Critical</span>
                  <span className="text-lg font-bold font-mono text-rose-400">{report.summary.criticalCount}</span>
                </div>
                <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                  <span className="text-xs text-slate-400 block font-serif">High</span>
                  <span className="text-lg font-bold font-mono text-amber-400">{report.summary.highCount}</span>
                </div>
                <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                  <span className="text-xs text-slate-400 block font-serif">Notices</span>
                  <span className="text-lg font-bold font-mono text-slate-300">{report.summary.mediumCount + report.summary.lowCount}</span>
                </div>
                <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                  <span className="text-xs text-slate-400 block font-serif">Passed</span>
                  <span className="text-lg font-bold font-mono text-emerald-400">{report.summary.passedCount}</span>
                </div>
              </div>

              {/* Priority Findings */}
              <div className="space-y-3 pt-2">
                <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider block font-serif">Audited Findings Summary</span>
                <div className="space-y-2">
                  {report.findings.map((f) => (
                    <div key={f.id} className="p-3 rounded-lg bg-slate-900 border border-slate-800 space-y-1 text-xs">
                      <div className="flex items-center justify-between">
                        <span className="font-semibold text-white font-serif">{f.title}</span>
                        <span className="font-mono text-[10px] uppercase text-slate-400">[{f.severity}]</span>
                      </div>
                      <p className="text-slate-400 font-serif">{f.description}</p>
                      {f.remediation && (
                        <div className="text-[11px] text-slate-300 pt-1 font-serif">
                          Fix: {f.remediation}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {activeTab === 'markdown' && (
            <div className="relative">
              <pre className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-slate-300 overflow-x-auto whitespace-pre-wrap max-h-[500px]">
                {markdownText}
              </pre>
            </div>
          )}

          {activeTab === 'json' && (
            <div className="relative">
              <pre className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-emerald-400 overflow-x-auto whitespace-pre-wrap max-h-[500px]">
                {jsonText}
              </pre>
            </div>
          )}
        </div>

        {/* Modal Footer Actions */}
        <div className="p-4 sm:px-6 border-t border-slate-800 bg-slate-950 flex items-center justify-between flex-wrap gap-3">
          <div className="text-xs text-slate-400 font-mono">
            Generated: {new Date(report.scanTimestamp).toLocaleDateString()}
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => window.print()}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-serif font-medium text-slate-300 bg-slate-900 hover:bg-slate-800 border border-slate-700 rounded-lg transition-colors"
            >
              <Printer className="w-3.5 h-3.5" />
              <span>Print / PDF</span>
            </button>

            {activeTab === 'markdown' && (
              <>
                <button
                  onClick={() => handleCopy(markdownText)}
                  className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-serif font-medium text-slate-300 bg-slate-900 hover:bg-slate-800 border border-slate-700 rounded-lg transition-colors"
                >
                  {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copied ? 'Copied' : 'Copy Markdown'}</span>
                </button>
                <button
                  onClick={() => handleDownloadFile(markdownText, `${report.hostname}-security-report.md`, 'text/markdown')}
                  className="flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-serif font-bold text-slate-950 bg-white hover:bg-slate-200 rounded-lg transition-colors"
                >
                  <Download className="w-3.5 h-3.5 text-slate-950" />
                  <span>Download .md</span>
                </button>
              </>
            )}

            {activeTab === 'json' && (
              <>
                <button
                  onClick={() => handleCopy(jsonText)}
                  className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-serif font-medium text-slate-300 bg-slate-900 hover:bg-slate-800 border border-slate-700 rounded-lg transition-colors"
                >
                  {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copied ? 'Copied' : 'Copy JSON'}</span>
                </button>
                <button
                  onClick={() => handleDownloadFile(jsonText, `${report.hostname}-security-report.json`, 'application/json')}
                  className="flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-serif font-bold text-slate-950 bg-white hover:bg-slate-200 rounded-lg transition-colors"
                >
                  <Download className="w-3.5 h-3.5 text-slate-950" />
                  <span>Download .json</span>
                </button>
              </>
            )}

            {activeTab === 'preview' && (
              <button
                onClick={() => handleDownloadFile(markdownText, `${report.hostname}-security-report.md`, 'text/markdown')}
                className="flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-serif font-bold text-slate-950 bg-white hover:bg-slate-200 rounded-lg transition-colors shadow-xs"
              >
                <Download className="w-3.5 h-3.5 text-slate-950" />
                <span>Save Report (.md)</span>
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
