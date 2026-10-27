import React, { useState } from 'react';
import { SqliAnalysisData } from '../types/security';
import { REMEDIATION_TEMPLATES } from '../utils/remediationTemplates';
import { 
  Database, 
  ShieldCheck, 
  ShieldAlert, 
  ShieldX, 
  AlertTriangle, 
  Code2, 
  CheckCircle2, 
  Copy, 
  Check, 
  Server,
  FileCode
} from 'lucide-react';

interface SqliAuditViewerProps {
  sqli: SqliAnalysisData;
  targetUrl: string;
}

export const SqliAuditViewer: React.FC<SqliAuditViewerProps> = ({ sqli, targetUrl }) => {
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [selectedSnippetTab, setSelectedSnippetTab] = useState<'express' | 'sqlParameterized' | 'nginx' | 'cloudflare'>('sqlParameterized');

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const getPostureBadge = (posture: SqliAnalysisData['injectionPosture']) => {
    switch (posture) {
      case 'Secure / Hardened':
        return {
          bg: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
          icon: ShieldCheck,
        };
      case 'Moderate':
        return {
          bg: 'bg-sky-500/10 text-sky-400 border-sky-500/30',
          icon: ShieldCheck,
        };
      case 'Warning':
        return {
          bg: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
          icon: ShieldAlert,
        };
      case 'High Risk':
      default:
        return {
          bg: 'bg-rose-500/10 text-rose-400 border-rose-500/30',
          icon: ShieldX,
        };
    }
  };

  const postureStyle = getPostureBadge(sqli.injectionPosture);
  const PostureIcon = postureStyle.icon;

  return (
    <div className="space-y-6 font-serif">
      {/* Top Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Posture Score */}
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>SQLi Defense Score</span>
            <Database className="w-4 h-4 text-slate-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-2xl font-bold text-white font-mono">{sqli.injectionRiskScore}</span>
            <span className="text-xs text-slate-500 font-mono">/ 100</span>
          </div>
          <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-medium border ${postureStyle.bg}`}>
            <PostureIcon className="w-3 h-3" />
            {sqli.injectionPosture}
          </span>
        </div>

        {/* DB Error Leakage Status */}
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>DB Error Disclosure</span>
            {sqli.dbErrorDisclosureDetected ? (
              <ShieldAlert className="w-4 h-4 text-rose-400" />
            ) : (
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            )}
          </div>
          <div className="text-base font-semibold text-white">
            {sqli.dbErrorDisclosureDetected ? (
              <span className="text-rose-400 font-bold">CWE-209 Leaked</span>
            ) : (
              <span className="text-emerald-400 font-bold">No Leaks Detected</span>
            )}
          </div>
          <p className="text-[11px] text-slate-400">
            {sqli.dbErrorDisclosureDetected
              ? `Signatures: ${sqli.detectedDbSignatures.join(', ')}`
              : 'Zero database syntax error tokens exposed in response body'}
          </p>
        </div>

        {/* WAF Status */}
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Web App Firewall (WAF)</span>
            <Server className="w-4 h-4 text-slate-400" />
          </div>
          <div className="text-base font-semibold text-white truncate" title={sqli.wafProvider || 'Not Detected'}>
            {sqli.wafDetected ? (
              <span className="text-emerald-400 font-bold">{sqli.wafProvider || 'WAF Active'}</span>
            ) : (
              <span className="text-amber-400 font-bold">Not Fingerprinted</span>
            )}
          </div>
          <p className="text-[11px] text-slate-400">
            {sqli.wafDetected
              ? 'Edge payload inspection active against OWASP A03 SQLi'
              : 'Direct connection; no edge WAF signatures identified'}
          </p>
        </div>

        {/* Query Parameter Surface */}
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>URL Parameters</span>
            <FileCode className="w-4 h-4 text-slate-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-2xl font-bold text-white font-mono">{sqli.parametersDetected.length}</span>
            <span className="text-xs text-slate-500">detected</span>
          </div>
          <p className="text-[11px] text-slate-400">
            {sqli.parametersDetected.filter((p) => p.riskTier === 'high').length > 0 ? (
              <span className="text-amber-400 font-medium">
                {sqli.parametersDetected.filter((p) => p.riskTier === 'high').length} high-risk SQL target param(s)
              </span>
            ) : (
              <span className="text-slate-400">Standard attack surface</span>
            )}
          </p>
        </div>
      </div>

      {/* Critical DB Error Warning Banner (if detected) */}
      {sqli.dbErrorDisclosureDetected && (
        <div className="p-5 rounded-xl bg-rose-500/10 border border-rose-500/30 space-y-2">
          <div className="flex items-center gap-2 text-rose-400 font-bold text-sm">
            <AlertTriangle className="w-5 h-5 shrink-0" />
            <span>CRITICAL: Database Error Information Disclosure (CWE-209 / OWASP A03:2021)</span>
          </div>
          <p className="text-xs text-rose-300 leading-relaxed">
            The target server returned raw database error signatures ({sqli.detectedDbSignatures.join(', ')}). Attackers actively trigger these errors to map table schemas, determine SQL syntax variants, and construct targeted SQL injection exploits.
          </p>
          <div className="pt-1 text-xs text-rose-200 font-mono">
            Remediation: Set <span className="px-1.5 py-0.5 rounded bg-rose-950 border border-rose-800">display_errors = Off</span> or handle exceptions with generic HTTP 500 error views.
          </div>
        </div>
      )}

      {/* Query Parameters Inspection Section */}
      <div className="p-6 rounded-xl bg-slate-900 border border-slate-800 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2">
            <Database className="w-5 h-5 text-slate-400" />
            <h3 className="text-base font-bold text-white">URL Query Parameter Hygiene & Injection Audit</h3>
          </div>
          <span className="text-xs font-mono text-slate-400">
            Analyzed: {targetUrl}
          </span>
        </div>

        {sqli.parametersDetected.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 font-semibold">
                  <th className="py-2.5 px-3">Parameter</th>
                  <th className="py-2.5 px-3">Sample Value</th>
                  <th className="py-2.5 px-3">Risk Tier</th>
                  <th className="py-2.5 px-3">Security Diagnostic & Recommendation</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {sqli.parametersDetected.map((param, idx) => {
                  const tierColors = {
                    high: 'bg-rose-500/10 text-rose-400 border-rose-500/30',
                    medium: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
                    low: 'bg-slate-800 text-slate-300 border-slate-700',
                  };

                  return (
                    <tr key={idx} className="hover:bg-slate-800/30 transition-colors">
                      <td className="py-2.5 px-3 font-mono font-bold text-white">
                        ?{param.name}=
                      </td>
                      <td className="py-2.5 px-3 font-mono text-slate-300 max-w-[140px] truncate" title={param.value}>
                        {param.value || '(empty)'}
                      </td>
                      <td className="py-2.5 px-3 whitespace-nowrap">
                        <span className={`inline-block px-2 py-0.5 rounded text-[11px] font-semibold border ${tierColors[param.riskTier]}`}>
                          {param.riskTier.toUpperCase()}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 text-slate-300 leading-relaxed">
                        {param.note}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="p-6 rounded-lg bg-slate-950 border border-slate-800 text-center space-y-2">
            <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto" />
            <h4 className="text-sm font-semibold text-white">No URL Query Parameters Detected</h4>
            <p className="text-xs text-slate-400 max-w-lg mx-auto">
              The analyzed URL does not expose query string parameters in this probe. This limits immediate URL-based SQL injection reconnaissance. Ensure backend REST/GraphQL APIs and POST body payloads utilize strict parameterized queries.
            </p>
          </div>
        )}
      </div>

      {/* Database Error Signature Inspection Table */}
      <div className="p-6 rounded-xl bg-slate-900 border border-slate-800 space-y-4">
        <div className="flex items-center gap-2 border-b border-slate-800 pb-3">
          <Code2 className="w-5 h-5 text-slate-400" />
          <h3 className="text-base font-bold text-white">Database Engine Signature Probes</h3>
        </div>

        <p className="text-xs text-slate-300 leading-relaxed">
          The scanner inspects the HTTP response body for error signatures associated with major database management systems. Disclosing database error strings allows attackers to fine-tune SQL injection attacks and map internal database schemas.
        </p>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 pt-1">
          {[
            { name: 'MySQL / MariaDB', check: 'SQL syntax.*MySQL', status: sqli.detectedDbSignatures.some(s => s.includes('MySQL')) },
            { name: 'PostgreSQL', check: 'PostgreSQL query failed / pg_query', status: sqli.detectedDbSignatures.some(s => s.includes('PostgreSQL')) },
            { name: 'Oracle Database', check: 'ORA-[0-9]{5}', status: sqli.detectedDbSignatures.some(s => s.includes('Oracle')) },
            { name: 'Microsoft SQL Server', check: 'OLE DB Provider for SQL Server', status: sqli.detectedDbSignatures.some(s => s.includes('Microsoft')) },
            { name: 'SQLite', check: 'SQLite3::SQLException / near syntax', status: sqli.detectedDbSignatures.some(s => s.includes('SQLite')) },
            { name: 'Generic SQL / ORM', check: 'SQLSTATE / Hibernate Grammar', status: sqli.detectedDbSignatures.some(s => s.includes('Generic')) },
          ].map((engine) => (
            <div key={engine.name} className="p-3 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between">
              <div className="space-y-0.5">
                <span className="text-xs font-semibold text-white block">{engine.name}</span>
                <span className="text-[11px] font-mono text-slate-500">{engine.check}</span>
              </div>
              <div>
                {engine.status ? (
                  <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/20 text-rose-300 border border-rose-500/40">
                    LEAK DETECTED
                  </span>
                ) : (
                  <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                    CLEAN
                  </span>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Parameterized Query & Prepared Statement Remediation Code Viewer */}
      <div className="p-6 rounded-xl bg-slate-900 border border-slate-800 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2">
            <Code2 className="w-5 h-5 text-emerald-400" />
            <div>
              <h3 className="text-base font-bold text-white">SQL Injection Remediation: Parameterized Queries</h3>
              <p className="text-xs text-slate-400">Production-ready code snippets implementing prepared statements & WAF protection</p>
            </div>
          </div>

          <div className="flex items-center gap-1.5 p-1 bg-slate-950 border border-slate-800 rounded-lg">
            <button
              onClick={() => setSelectedSnippetTab('sqlParameterized')}
              className={`px-2.5 py-1 text-xs rounded transition-colors ${
                selectedSnippetTab === 'sqlParameterized' ? 'bg-slate-800 text-white font-bold' : 'text-slate-400 hover:text-white'
              }`}
            >
              ANSI SQL
            </button>
            <button
              onClick={() => setSelectedSnippetTab('express')}
              className={`px-2.5 py-1 text-xs rounded transition-colors ${
                selectedSnippetTab === 'express' ? 'bg-slate-800 text-white font-bold' : 'text-slate-400 hover:text-white'
              }`}
            >
              Node.js / Express
            </button>
            <button
              onClick={() => setSelectedSnippetTab('nginx')}
              className={`px-2.5 py-1 text-xs rounded transition-colors ${
                selectedSnippetTab === 'nginx' ? 'bg-slate-800 text-white font-bold' : 'text-slate-400 hover:text-white'
              }`}
            >
              Nginx Filter
            </button>
            <button
              onClick={() => setSelectedSnippetTab('cloudflare')}
              className={`px-2.5 py-1 text-xs rounded transition-colors ${
                selectedSnippetTab === 'cloudflare' ? 'bg-slate-800 text-white font-bold' : 'text-slate-400 hover:text-white'
              }`}
            >
              Cloudflare WAF
            </button>
          </div>
        </div>

        {/* Snippet Display */}
        <div className="relative">
          <pre className="p-4 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-slate-200 overflow-x-auto leading-relaxed">
            {REMEDIATION_TEMPLATES.sqliDefense[selectedSnippetTab] || ''}
          </pre>

          <button
            onClick={() =>
              copyToClipboard(
                REMEDIATION_TEMPLATES.sqliDefense[selectedSnippetTab] || '',
                selectedSnippetTab
              )
            }
            className="absolute top-2.5 right-2.5 px-2.5 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white text-xs border border-slate-700 flex items-center gap-1.5 transition-colors"
          >
            {copiedKey === selectedSnippetTab ? (
              <>
                <Check className="w-3.5 h-3.5 text-emerald-400" />
                <span className="text-emerald-400 font-bold">Copied!</span>
              </>
            ) : (
              <>
                <Copy className="w-3.5 h-3.5" />
                <span>Copy Code</span>
              </>
            )}
          </button>
        </div>

        <div className="text-xs text-slate-400 space-y-1">
          <span className="font-semibold text-slate-300">Security Rule (OWASP A03 / CWE-89): </span>
          <span>
            Never interpolate or concatenate untrusted user input directly into SQL strings. Always bind parameters separately using database engine prepared statements or established ORM parameterization.
          </span>
        </div>
      </div>
    </div>
  );
};
