import React, { useState } from 'react';
import { SecurityHeaderItem } from '../types/security';
import { CheckCircle2, AlertTriangle, AlertOctagon, Copy, Check } from 'lucide-react';

interface SecurityHeadersViewerProps {
  headers: SecurityHeaderItem[];
}

export const SecurityHeadersViewer: React.FC<SecurityHeadersViewerProps> = ({ headers }) => {
  const [copiedName, setCopiedName] = useState<string | null>(null);
  const [filter, setFilter] = useState<'all' | 'optimal' | 'missing' | 'warning'>('all');

  const filteredHeaders = headers.filter((h) => {
    if (filter === 'all') return true;
    if (filter === 'optimal') return h.status === 'optimal';
    if (filter === 'missing') return h.status === 'missing';
    if (filter === 'warning') return h.status === 'warning' || h.status === 'insecure';
    return true;
  });

  const handleCopy = (name: string, val: string) => {
    navigator.clipboard.writeText(val);
    setCopiedName(name);
    setTimeout(() => setCopiedName(null), 2000);
  };

  const getStatusBadge = (status: SecurityHeaderItem['status']) => {
    switch (status) {
      case 'optimal':
        return {
          icon: CheckCircle2,
          color: 'text-emerald-400 border-emerald-500/30 bg-emerald-500/10',
          label: 'CONFIGURED',
        };
      case 'warning':
        return {
          icon: AlertTriangle,
          color: 'text-amber-400 border-amber-500/30 bg-amber-500/10',
          label: 'SUB-OPTIMAL',
        };
      case 'insecure':
        return {
          icon: AlertOctagon,
          color: 'text-rose-400 border-rose-500/30 bg-rose-500/10',
          label: 'INSECURE',
        };
      case 'missing':
      default:
        return {
          icon: AlertOctagon,
          color: 'text-rose-400 border-rose-500/30 bg-rose-500/10',
          label: 'MISSING',
        };
    }
  };

  return (
    <div className="space-y-4 font-serif">
      {/* Top Filter Bar */}
      <div className="flex items-center justify-between flex-wrap gap-2">
        <div className="text-xs text-slate-400">
          Showing <span className="text-white font-mono font-medium">{filteredHeaders.length}</span> of {headers.length} audited response headers
        </div>

        <div className="flex items-center gap-1 p-1 bg-slate-900 border border-slate-800 rounded-lg">
          {(['all', 'optimal', 'warning', 'missing'] as const).map((mode) => {
            const isActive = filter === mode;
            return (
              <button
                key={mode}
                onClick={() => setFilter(mode)}
                className={`px-3 py-1 text-xs font-serif font-medium rounded-md capitalize transition-colors ${
                  isActive ? 'bg-slate-800 text-white font-bold' : 'text-slate-400 hover:text-white'
                }`}
              >
                {mode}
              </button>
            );
          })}
        </div>
      </div>

      {/* Headers Grid */}
      <div className="grid grid-cols-1 gap-3">
        {filteredHeaders.map((header) => {
          const badge = getStatusBadge(header.status);
          const Icon = badge.icon;

          return (
            <div
              key={header.name}
              className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3"
            >
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <div className="flex items-center gap-2.5">
                  <Icon className={`w-4 h-4 shrink-0 ${badge.color.split(' ')[0]}`} />
                  <span className="text-sm font-semibold font-mono text-white">
                    {header.name}
                  </span>
                  <span className="text-[11px] text-slate-500">· {header.importance} priority</span>
                </div>

                <div className="flex items-center gap-2 self-start sm:self-auto">
                  <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${badge.color}`}>
                    {badge.label}
                  </span>
                  {header.value && (
                    <button
                      type="button"
                      onClick={() => handleCopy(header.name, header.value || '')}
                      className="p-1 text-slate-400 hover:text-white rounded hover:bg-slate-800"
                      title="Copy header value"
                    >
                      {copiedName === header.name ? (
                        <Check className="w-3.5 h-3.5 text-emerald-400" />
                      ) : (
                        <Copy className="w-3.5 h-3.5" />
                      )}
                    </button>
                  )}
                </div>
              </div>

              {/* Description */}
              <p className="text-xs text-slate-300 leading-relaxed font-serif">
                {header.description}
              </p>

              {/* Received Value if present */}
              {header.value ? (
                <div className="p-2.5 rounded bg-slate-950 border border-slate-800 overflow-x-auto">
                  <span className="text-[10px] uppercase tracking-wider text-slate-500 block mb-1">
                    Detected Value:
                  </span>
                  <code className="text-xs font-mono text-slate-200 whitespace-pre-wrap break-all">
                    {header.value}
                  </code>
                </div>
              ) : (
                <div className="text-xs text-rose-400 font-mono italic">
                  Header omitted from server response.
                </div>
              )}

              {/* Best practice recommendation */}
              <div className="text-xs text-slate-400 pt-1 border-t border-slate-800 flex items-start gap-1.5">
                <span className="text-white font-semibold shrink-0">Recommendation:</span>
                <span className="text-slate-300 font-serif">{header.recommendation}</span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
