import React, { useState } from 'react';
import { REMEDIATION_TEMPLATES } from '../utils/remediationTemplates';
import { Terminal, Copy, Check } from 'lucide-react';

export const RemediationGuide: React.FC = () => {
  const [activePlatform, setActivePlatform] = useState<'nginx' | 'apache' | 'express' | 'cloudflare'>('nginx');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const handleCopy = (key: string, code: string) => {
    navigator.clipboard.writeText(code);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const templatesList = Object.entries(REMEDIATION_TEMPLATES);

  return (
    <div className="space-y-6 max-w-5xl mx-auto font-serif">
      {/* Title & Platform Switcher */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-5 rounded-xl bg-slate-900 border border-slate-800">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-slate-800 border border-slate-700 flex items-center justify-center shrink-0">
            <Terminal className="w-5 h-5 text-slate-300" />
          </div>
          <div>
            <h3 className="text-base font-semibold text-white">Web Server Hardening Playbook</h3>
            <p className="text-xs text-slate-400 mt-0.5 font-serif">
              Production-grade defensive configurations for web servers, reverse proxies, and applications.
            </p>
          </div>
        </div>

        {/* Platform segmented buttons */}
        <div className="flex items-center gap-1 p-1 bg-slate-950 rounded-lg border border-slate-800">
          {(['nginx', 'apache', 'express', 'cloudflare'] as const).map((plat) => (
            <button
              key={plat}
              onClick={() => setActivePlatform(plat)}
              className={`px-3 py-1.5 text-xs font-mono font-medium rounded-md capitalize transition-colors ${
                activePlatform === plat
                  ? 'bg-slate-800 text-white shadow-xs font-bold'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              {plat}
            </button>
          ))}
        </div>
      </div>

      {/* Hardening Blocks */}
      <div className="space-y-4">
        {templatesList.map(([key, tpl]) => {
          const code = (tpl as any)[activePlatform] || '';
          if (!code) return null;

          return (
            <div key={key} className="rounded-xl border border-slate-800 bg-slate-900 overflow-hidden">
              <div className="p-4 flex items-center justify-between border-b border-slate-800 bg-slate-950">
                <span className="text-xs font-semibold text-white font-mono">{tpl.title}</span>
                <button
                  onClick={() => handleCopy(key, code)}
                  className="flex items-center gap-1 px-2.5 py-1 text-xs font-serif font-medium text-slate-300 hover:text-white bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded transition-colors"
                >
                  {copiedKey === key ? (
                    <>
                      <Check className="w-3.5 h-3.5 text-emerald-400" />
                      <span className="text-emerald-400">Copied</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5 text-slate-400" />
                      <span>Copy Snippet</span>
                    </>
                  )}
                </button>
              </div>
              <div className="p-4 bg-slate-950 overflow-x-auto">
                <pre className="text-xs font-mono text-slate-200 whitespace-pre">
                  {code}
                </pre>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
