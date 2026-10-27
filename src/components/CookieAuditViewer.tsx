import React from 'react';
import { CookieItem } from '../types/security';
import { Cookie, CheckCircle2, AlertTriangle, XCircle } from 'lucide-react';

interface CookieAuditViewerProps {
  cookies: CookieItem[];
}

export const CookieAuditViewer: React.FC<CookieAuditViewerProps> = ({ cookies }) => {
  const insecureCount = cookies.filter((c) => !c.secure).length;
  const nonHttpOnlyCount = cookies.filter((c) => !c.httpOnly).length;

  return (
    <div className="space-y-6 font-serif">
      {/* Overview Banner */}
      <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-slate-800 border border-slate-700 flex items-center justify-center shrink-0">
            <Cookie className="w-5 h-5 text-slate-300" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-base font-semibold text-white">HTTP Cookie Security Attributes</h3>
              <span className="text-xs font-mono text-slate-300 px-2 py-0.5 rounded bg-slate-800 border border-slate-700">
                {cookies.length} Cookies Audited
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5 font-serif">
              Auditing Secure, HttpOnly, and SameSite attributes to protect against XSS session theft and CSRF.
            </p>
          </div>
        </div>

        {/* Quick Cookie Health Tokens */}
        <div className="flex items-center gap-3 shrink-0">
          <div className="text-center px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800">
            <span className="text-[10px] text-slate-400 uppercase tracking-wider block font-serif">Insecure Flags</span>
            <span className={`text-sm font-bold font-mono ${insecureCount > 0 ? 'text-rose-400' : 'text-emerald-400'}`}>
              {insecureCount}
            </span>
          </div>

          <div className="text-center px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800">
            <span className="text-[10px] text-slate-400 uppercase tracking-wider block font-serif">No HttpOnly</span>
            <span className={`text-sm font-bold font-mono ${nonHttpOnlyCount > 0 ? 'text-amber-400' : 'text-emerald-400'}`}>
              {nonHttpOnlyCount}
            </span>
          </div>
        </div>
      </div>

      {/* Cookies Table or Empty State */}
      {cookies.length === 0 ? (
        <div className="p-8 text-center bg-slate-900 border border-slate-800 rounded-xl space-y-2">
          <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto" />
          <h4 className="text-sm font-semibold text-white">No Cookies Set in Initial Response</h4>
          <p className="text-xs text-slate-400 max-w-md mx-auto font-serif">
            The target server did not transmit any `Set-Cookie` response headers during the initial probe, minimizing initial browser surface exposure.
          </p>
        </div>
      ) : (
        <div className="rounded-xl border border-slate-800 bg-slate-900 overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950 border-b border-slate-800 text-slate-400 uppercase font-mono text-[11px]">
                <tr>
                  <th className="py-3 px-4 font-serif">Cookie Name</th>
                  <th className="py-3 px-4 text-center font-serif">Secure</th>
                  <th className="py-3 px-4 text-center font-serif">HttpOnly</th>
                  <th className="py-3 px-4 text-center font-serif">SameSite</th>
                  <th className="py-3 px-4 font-serif">Path & Scope</th>
                  <th className="py-3 px-4 font-serif">Risk Profile</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800 font-mono">
                {cookies.map((cookie, idx) => {
                  return (
                    <tr key={idx} className="hover:bg-slate-800/40 transition-colors">
                      <td className="py-3 px-4 font-semibold text-white break-all">
                        {cookie.name}
                        {cookie.prefix !== 'none' && (
                          <span className="ml-1.5 text-[10px] text-slate-300 px-1 py-0.2 bg-slate-800 rounded border border-slate-700">
                            {cookie.prefix.toUpperCase()} PREFIX
                          </span>
                        )}
                      </td>

                      {/* Secure Flag */}
                      <td className="py-3 px-4 text-center">
                        {cookie.secure ? (
                          <span className="inline-flex items-center gap-1 text-emerald-400">
                            <CheckCircle2 className="w-4 h-4" />
                            <span className="hidden sm:inline text-[11px]">Yes</span>
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 text-rose-400">
                            <XCircle className="w-4 h-4" />
                            <span className="hidden sm:inline text-[11px]">No</span>
                          </span>
                        )}
                      </td>

                      {/* HttpOnly Flag */}
                      <td className="py-3 px-4 text-center">
                        {cookie.httpOnly ? (
                          <span className="inline-flex items-center gap-1 text-emerald-400">
                            <CheckCircle2 className="w-4 h-4" />
                            <span className="hidden sm:inline text-[11px]">Yes</span>
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 text-amber-400">
                            <AlertTriangle className="w-4 h-4" />
                            <span className="hidden sm:inline text-[11px]">No</span>
                          </span>
                        )}
                      </td>

                      {/* SameSite */}
                      <td className="py-3 px-4 text-center">
                        <span
                          className={`px-2 py-0.5 rounded text-[11px] border ${
                            cookie.sameSite === 'Strict'
                              ? 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30'
                              : cookie.sameSite === 'Lax'
                              ? 'text-sky-400 bg-sky-500/10 border-sky-500/30'
                              : 'text-rose-400 bg-rose-500/10 border-rose-500/30'
                          }`}
                        >
                          {cookie.sameSite}
                        </span>
                      </td>

                      {/* Path & Domain */}
                      <td className="py-3 px-4 text-slate-400 text-[11px] font-serif">
                        <div>Path: {cookie.path || '/'}</div>
                        {cookie.domain && <div>Domain: {cookie.domain}</div>}
                      </td>

                      {/* Warnings / Risk */}
                      <td className="py-3 px-4 font-serif">
                        {cookie.warnings.length > 0 ? (
                          <div className="space-y-1">
                            {cookie.warnings.map((w, wIdx) => (
                              <div key={wIdx} className="text-[11px] text-rose-300 flex items-center gap-1">
                                <AlertTriangle className="w-3 h-3 text-rose-400 shrink-0" />
                                <span>{w}</span>
                              </div>
                            ))}
                          </div>
                        ) : (
                          <span className="text-emerald-400 text-[11px] flex items-center gap-1">
                            <CheckCircle2 className="w-3.5 h-3.5" />
                            Secure flags applied
                          </span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};
