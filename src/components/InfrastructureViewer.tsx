import React from 'react';
import { RedirectChainData, InfrastructureData } from '../types/security';
import { 
  ArrowRight, 
  FileCode, 
  Server, 
  MapPin, 
  Lock, 
  Unlock, 
  CheckCircle2, 
  XCircle 
} from 'lucide-react';

interface InfrastructureViewerProps {
  redirects: RedirectChainData;
  infrastructure: InfrastructureData;
}

export const InfrastructureViewer: React.FC<InfrastructureViewerProps> = ({
  redirects,
  infrastructure,
}) => {
  return (
    <div className="space-y-6 font-serif">
      {/* Redirect Chain Visualization */}
      <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-4">
        <div className="flex items-center justify-between flex-wrap gap-2">
          <div>
            <h3 className="text-base font-semibold text-white">Redirect Chain & HTTPS Enforcement</h3>
            <p className="text-xs text-slate-400 mt-0.5 font-serif">
              Tracks HTTP-to-HTTPS upgrade, status codes, and prevents downgrade attacks.
            </p>
          </div>
          <span
            className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
              redirects.hasDowngrade
                ? 'text-rose-400 border-rose-500/30 bg-rose-500/10'
                : redirects.enforcesHttps
                ? 'text-emerald-400 border-emerald-500/30 bg-emerald-500/10'
                : 'text-amber-400 border-amber-500/30 bg-amber-500/10'
            }`}
          >
            {redirects.hasDowngrade
              ? 'PROTOCOL DOWNGRADE DETECTED'
              : redirects.enforcesHttps
              ? 'STRICT HTTPS ENFORCED'
              : 'PLAINTEXT HTTP PERMITTED'}
          </span>
        </div>

        {/* Visual Chain flow */}
        <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 overflow-x-auto">
          <div className="flex items-center gap-3 min-w-max">
            {redirects.hops.map((hop, idx) => {
              const isHttps = hop.protocol === 'https:';
              const isLast = idx === redirects.hops.length - 1;

              return (
                <React.Fragment key={idx}>
                  <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 flex flex-col gap-1 w-64 shrink-0 font-mono text-xs">
                    <div className="flex items-center justify-between">
                      <span className="text-[10px] text-slate-500 font-serif">Hop #{idx + 1}</span>
                      <span
                        className={`text-[10px] font-bold px-1.5 py-0.2 rounded ${
                          hop.statusCode >= 200 && hop.statusCode < 300
                            ? 'bg-emerald-500/10 text-emerald-400'
                            : hop.statusCode >= 300 && hop.statusCode < 400
                            ? 'bg-cyan-500/10 text-cyan-400'
                            : 'bg-rose-500/10 text-rose-400'
                        }`}
                      >
                        {hop.statusCode}
                      </span>
                    </div>

                    <div className="flex items-center gap-1.5 text-white font-medium truncate" title={hop.url}>
                      {isHttps ? (
                        <Lock className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                      ) : (
                        <Unlock className="w-3.5 h-3.5 text-amber-400 shrink-0" />
                      )}
                      <span className="truncate">{hop.url}</span>
                    </div>

                    {hop.location && (
                      <div className="text-[10px] text-slate-400 truncate mt-0.5">
                        ➜ <span className="text-slate-200">{hop.location}</span>
                      </div>
                    )}
                  </div>

                  {!isLast && (
                    <ArrowRight className="w-4 h-4 text-slate-600 shrink-0" />
                  )}
                </React.Fragment>
              );
            })}
          </div>
        </div>
      </div>

      {/* Host Network & Geolocation */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Network Specs */}
        <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
          <div className="flex items-center gap-2">
            <Server className="w-4 h-4 text-slate-400" />
            <h4 className="text-sm font-semibold text-white">Network & Autonomous System</h4>
          </div>

          <div className="divide-y divide-slate-800 text-xs">
            <div className="py-2.5 flex items-center justify-between">
              <span className="text-slate-400 font-serif">Primary IP Address</span>
              <span className="font-mono text-white font-medium">{infrastructure.ipAddress || 'Unresolved'}</span>
            </div>

            {infrastructure.reverseDns && (
              <div className="py-2.5 flex items-center justify-between">
                <span className="text-slate-400 font-serif">Reverse DNS (PTR)</span>
                <span className="font-mono text-slate-200 font-medium truncate max-w-[200px]" title={infrastructure.reverseDns}>
                  {infrastructure.reverseDns}
                </span>
              </div>
            )}

            <div className="py-2.5 flex items-center justify-between">
              <span className="text-slate-400 font-serif">ASN / Provider</span>
              <span className="text-white font-medium font-serif">{infrastructure.asnOrg || infrastructure.asn || 'Not detected'}</span>
            </div>

            <div className="py-2.5 flex items-center justify-between">
              <span className="text-slate-400 font-serif">Server Banner Header</span>
              <span className="font-mono text-amber-300">{infrastructure.serverBanner || 'Hidden (Optimal)'}</span>
            </div>
          </div>
        </div>

        {/* Location & Sensitive Endpoints */}
        <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
          <div className="flex items-center gap-2">
            <MapPin className="w-4 h-4 text-slate-400" />
            <h4 className="text-sm font-semibold text-white">Location & Discovery Endpoints</h4>
          </div>

          <div className="divide-y divide-slate-800 text-xs">
            <div className="py-2.5 flex items-center justify-between">
              <span className="text-slate-400 font-serif">Geographic Region</span>
              <span className="text-white font-medium font-serif">
                {infrastructure.city ? `${infrastructure.city}, ` : ''}
                {infrastructure.country || 'Global Anycast CDN'}
              </span>
            </div>

            {/* security.txt */}
            <div className="py-2.5 flex items-center justify-between">
              <span className="text-slate-400 font-serif">RFC 9116 security.txt</span>
              <div className="flex items-center gap-1.5">
                {infrastructure.hasSecurityTxt ? (
                  <span className="text-emerald-400 font-mono text-[11px] flex items-center gap-1">
                    <CheckCircle2 className="w-3.5 h-3.5" /> Present
                  </span>
                ) : (
                  <span className="text-slate-500 font-mono text-[11px] flex items-center gap-1">
                    <XCircle className="w-3.5 h-3.5" /> Not Found
                  </span>
                )}
              </div>
            </div>

            {/* robots.txt */}
            <div className="py-2.5 flex items-center justify-between">
              <span className="text-slate-400 font-serif">Crawler Policy (robots.txt)</span>
              <span className="text-slate-300 font-mono text-[11px]">
                {infrastructure.hasRobotsTxt ? 'Present' : 'Not configured'}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Disallowed Paths Exposure from robots.txt */}
      {infrastructure.robotsDisallowedPaths.length > 0 && (
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
          <span className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
            <FileCode className="w-3.5 h-3.5 text-slate-400" />
            Disallowed Crawler Endpoints Disclosed in robots.txt ({infrastructure.robotsDisallowedPaths.length})
          </span>
          <p className="text-[11px] text-slate-400 font-serif">
            Note: Disallowing paths in robots.txt tells search engines not to index them, but reveals internal URL naming conventions to crawlers.
          </p>
          <div className="flex flex-wrap gap-1.5 pt-1">
            {infrastructure.robotsDisallowedPaths.map((p, i) => (
              <span
                key={i}
                className="px-2 py-0.5 rounded bg-slate-950 font-mono text-[11px] text-amber-300 border border-slate-800"
              >
                {p}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
