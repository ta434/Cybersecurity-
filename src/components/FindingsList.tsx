import React, { useState } from 'react';
import { SecurityFinding, SeverityLevel } from '../types/security';
import { 
  AlertOctagon, 
  AlertTriangle, 
  Info, 
  CheckCircle2, 
  ChevronDown, 
  ChevronUp, 
  Copy, 
  Check, 
  Code
} from 'lucide-react';

interface FindingsListProps {
  findings: SecurityFinding[];
}

export const FindingsList: React.FC<FindingsListProps> = ({ findings }) => {
  const [filter, setFilter] = useState<SeverityLevel | 'all'>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [activeSnippetTab, setActiveSnippetTab] = useState<Record<string, 'nginx' | 'apache' | 'express' | 'cloudflare'>>({});

  const filteredFindings = findings.filter((f) => {
    if (filter !== 'all' && f.severity !== filter) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      return (
        f.title.toLowerCase().includes(q) ||
        f.description.toLowerCase().includes(q) ||
        f.category.toLowerCase().includes(q)
      );
    }
    return true;
  });

  const getSeverityStyle = (s: SeverityLevel) => {
    switch (s) {
      case 'critical':
        return {
          icon: AlertOctagon,
          textColor: 'text-rose-400',
          badgeBg: 'bg-rose-500/10 text-rose-300 border-rose-500/30',
          label: 'CRITICAL',
        };
      case 'high':
        return {
          icon: AlertTriangle,
          textColor: 'text-amber-400',
          badgeBg: 'bg-amber-500/10 text-amber-300 border-amber-500/30',
          label: 'HIGH',
        };
      case 'medium':
        return {
          icon: AlertTriangle,
          textColor: 'text-yellow-400',
          badgeBg: 'bg-yellow-500/10 text-yellow-300 border-yellow-500/30',
          label: 'MEDIUM',
        };
      case 'low':
        return {
          icon: Info,
          textColor: 'text-sky-400',
          badgeBg: 'bg-sky-500/10 text-sky-300 border-sky-500/30',
          label: 'LOW',
        };
      case 'info':
        return {
          icon: Info,
          textColor: 'text-slate-400',
          badgeBg: 'bg-slate-800 text-slate-300 border-slate-700',
          label: 'INFO',
        };
      case 'passed':
      default:
        return {
          icon: CheckCircle2,
          textColor: 'text-emerald-400',
          badgeBg: 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30',
          label: 'PASSED',
        };
    }
  };

  const handleCopyCode = (id: string, code: string) => {
    navigator.clipboard.writeText(code);
    setCopiedKey(id);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const counts = {
    all: findings.length,
    critical: findings.filter((f) => f.severity === 'critical').length,
    high: findings.filter((f) => f.severity === 'high').length,
    medium: findings.filter((f) => f.severity === 'medium').length,
    low: findings.filter((f) => f.severity === 'low').length,
    passed: findings.filter((f) => f.severity === 'passed').length,
  };

  return (
    <div className="space-y-4 font-serif">
      {/* Controls Row */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
        {/* Interactive Segmented Filter Tabs */}
        <div className="flex items-center gap-1 p-1 bg-slate-900 border border-slate-800 rounded-lg overflow-x-auto">
          {(['all', 'critical', 'high', 'medium', 'low', 'passed'] as const).map((lvl) => {
            const count = counts[lvl];
            const isActive = filter === lvl;
            return (
              <button
                key={lvl}
                onClick={() => setFilter(lvl)}
                className={`px-3 py-1.5 text-xs font-serif font-medium rounded-md whitespace-nowrap transition-colors flex items-center gap-1.5 ${
                  isActive
                    ? 'bg-slate-800 text-white font-bold'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <span className="capitalize">{lvl}</span>
                <span className="font-mono text-[11px] px-1.5 py-0.2 rounded bg-slate-950 text-slate-400">
                  {count}
                </span>
              </button>
            );
          })}
        </div>

        {/* Search Input */}
        <div className="relative w-full sm:w-64">
          <input
            type="text"
            placeholder="Search findings..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full px-3 py-1.5 text-xs bg-slate-900 border border-slate-800 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:border-slate-600 font-serif"
          />
        </div>
      </div>

      {/* Findings List Items */}
      {filteredFindings.length === 0 ? (
        <div className="p-8 text-center bg-slate-900 border border-slate-800 rounded-xl text-slate-400 text-sm">
          No findings matching the selected filters.
        </div>
      ) : (
        <div className="space-y-3">
          {filteredFindings.map((finding) => {
            const style = getSeverityStyle(finding.severity);
            const Icon = style.icon;
            const isExpanded = expandedId === finding.id;
            const currentTab = activeSnippetTab[finding.id] || 'nginx';

            return (
              <div
                key={finding.id}
                className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden transition-all"
              >
                {/* Header Row */}
                <div
                  onClick={() => setExpandedId(isExpanded ? null : finding.id)}
                  className="p-4 flex items-start justify-between gap-4 cursor-pointer hover:bg-slate-800/40 transition-colors"
                >
                  <div className="flex items-start gap-3">
                    <div className="mt-0.5 shrink-0">
                      <Icon className={`w-5 h-5 ${style.textColor}`} />
                    </div>
                    <div className="space-y-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-sm font-semibold text-white">
                          {finding.title}
                        </span>
                        {/* Unboxed metadata tags */}
                        <div className="flex items-center gap-1.5 text-xs text-slate-500">
                          <span>{finding.category.toUpperCase()}</span>
                          {finding.owasp && (
                            <>
                              <span aria-hidden="true">·</span>
                              <span className="text-slate-400">{finding.owasp}</span>
                            </>
                          )}
                          {finding.cwe && (
                            <>
                              <span aria-hidden="true">·</span>
                              <span className="text-slate-400">{finding.cwe}</span>
                            </>
                          )}
                        </div>
                      </div>
                      <p className="text-xs text-slate-400 leading-relaxed font-serif">
                        {finding.description}
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center gap-3 shrink-0">
                    <span
                      className={`text-[10px] font-mono px-2 py-0.5 rounded border ${style.badgeBg} uppercase tracking-wider`}
                    >
                      {style.label}
                    </span>
                    <button
                      type="button"
                      aria-label={isExpanded ? 'Collapse' : 'Expand'}
                      className="p-1 text-slate-400 hover:text-white"
                    >
                      {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                    </button>
                  </div>
                </div>

                {/* Expanded Details & Remediation */}
                {isExpanded && (
                  <div className="p-4 border-t border-slate-800/80 bg-slate-950/60 space-y-4">
                    {/* Impact Statement */}
                    {finding.impact && (
                      <div className="space-y-1">
                        <span className="text-xs font-semibold text-rose-400 uppercase tracking-wider">
                          Security Impact
                        </span>
                        <p className="text-xs text-slate-300 leading-relaxed font-serif">
                          {finding.impact}
                        </p>
                      </div>
                    )}

                    {/* Remediation Guide */}
                    {finding.remediation && (
                      <div className="space-y-1.5">
                        <span className="text-xs font-semibold text-white uppercase tracking-wider flex items-center gap-1.5">
                          <Code className="w-3.5 h-3.5 text-slate-400" />
                          Recommended Remediation
                        </span>
                        <p className="text-xs text-slate-300 leading-relaxed font-serif">
                          {finding.remediation}
                        </p>
                      </div>
                    )}

                    {/* Code Snippet Tabs */}
                    {finding.codeSnippet && (
                      <div className="space-y-2 pt-2">
                        <div className="flex items-center justify-between text-xs">
                          <div className="flex items-center gap-1 p-0.5 bg-slate-900 rounded border border-slate-800">
                            {(['nginx', 'apache', 'express', 'cloudflare'] as const).map((tab) => {
                              if (!finding.codeSnippet?.[tab]) return null;
                              const isActive = currentTab === tab;
                              return (
                                <button
                                  key={tab}
                                  type="button"
                                  onClick={() =>
                                    setActiveSnippetTab((prev) => ({ ...prev, [finding.id]: tab }))
                                  }
                                  className={`px-2.5 py-1 text-[11px] font-mono rounded capitalize transition-colors ${
                                    isActive
                                      ? 'bg-slate-800 text-white shadow-sm'
                                      : 'text-slate-400 hover:text-slate-200'
                                  }`}
                                >
                                  {tab}
                                </button>
                              );
                            })}
                          </div>

                          <button
                            type="button"
                            onClick={() => {
                              const snippet = finding.codeSnippet?.[currentTab] || '';
                              handleCopyCode(`${finding.id}-${currentTab}`, snippet);
                            }}
                            className="flex items-center gap-1 px-2.5 py-1 text-[11px] font-medium text-slate-300 hover:text-white bg-slate-900 hover:bg-slate-800 border border-slate-800 rounded transition-colors"
                          >
                            {copiedKey === `${finding.id}-${currentTab}` ? (
                              <>
                                <Check className="w-3 h-3 text-emerald-400" />
                                <span className="text-emerald-400">Copied</span>
                              </>
                            ) : (
                              <>
                                <Copy className="w-3 h-3 text-slate-400" />
                                <span>Copy Config</span>
                              </>
                            )}
                          </button>
                        </div>

                        {/* Code Block */}
                        <div className="relative rounded-lg bg-slate-950 border border-slate-800 p-3 overflow-x-auto">
                          <pre className="text-xs font-mono text-slate-300 whitespace-pre">
                            {finding.codeSnippet[currentTab]}
                          </pre>
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
