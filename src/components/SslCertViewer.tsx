import React from 'react';
import { SslCertificateInfo } from '../types/security';
import { Lock, AlertTriangle, ShieldX, ShieldCheck } from 'lucide-react';

interface SslCertViewerProps {
  ssl: SslCertificateInfo;
  hostname: string;
}

export const SslCertViewer: React.FC<SslCertViewerProps> = ({ ssl, hostname }) => {
  const isExpiring = ssl.isExpiringSoon;
  const isExpired = ssl.isExpired;

  const getStatusBadge = () => {
    if (isExpired) {
      return {
        text: 'EXPIRED',
        color: 'text-rose-400 border-rose-500/30 bg-rose-500/10',
        icon: ShieldX,
      };
    }
    if (ssl.status === 'untrusted') {
      return {
        text: 'UNTRUSTED / SELF-SIGNED',
        color: 'text-rose-400 border-rose-500/30 bg-rose-500/10',
        icon: ShieldX,
      };
    }
    if (isExpiring) {
      return {
        text: 'EXPIRING SOON (<30 DAYS)',
        color: 'text-amber-400 border-amber-500/30 bg-amber-500/10',
        icon: AlertTriangle,
      };
    }
    if (ssl.status === 'valid') {
      return {
        text: 'VALID & TRUSTED',
        color: 'text-emerald-400 border-emerald-500/30 bg-emerald-500/10',
        icon: ShieldCheck,
      };
    }
    return {
      text: 'NO SSL DETECTED',
      color: 'text-slate-400 border-slate-700 bg-slate-800',
      icon: AlertTriangle,
    };
  };

  const status = getStatusBadge();

  return (
    <div className="space-y-6 font-serif">
      {/* Expiry Banner */}
      <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-slate-800 border border-slate-700 flex items-center justify-center shrink-0">
            <Lock className="w-5 h-5 text-slate-300" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-base font-semibold text-white">TLS / SSL Encryption Certificate</h3>
              <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${status.color}`}>
                {status.text}
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              {ssl.daysRemaining > 0
                ? `Valid for another ${ssl.daysRemaining} days (expires ${new Date(ssl.validTo).toLocaleDateString()})`
                : ssl.isExpired
                ? `Certificate expired on ${new Date(ssl.validTo).toLocaleDateString()}`
                : 'No certificate active on port 443'}
            </p>
          </div>
        </div>

        {/* Days remaining badge / meter */}
        {ssl.daysRemaining > 0 && (
          <div className="text-right shrink-0">
            <div className="text-2xl font-bold font-mono text-white tabular-nums">
              {ssl.daysRemaining} <span className="text-xs font-serif text-slate-400 font-normal">days left</span>
            </div>
            <div className="w-32 bg-slate-800 h-1.5 rounded-full overflow-hidden mt-1 ml-auto">
              <div
                className={`h-full ${
                  ssl.daysRemaining > 30 ? 'bg-emerald-500' : 'bg-amber-500'
                } rounded-full`}
                style={{ width: `${Math.min(100, (ssl.daysRemaining / 90) * 100)}%` }}
              />
            </div>
          </div>
        )}
      </div>

      {/* Protocol & Cipher Info */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
          <span className="text-xs text-slate-400 block mb-1">Negotiated Protocol</span>
          <span className="text-sm font-semibold font-mono text-white">
            {ssl.protocolVersion || 'TLSv1.3'}
          </span>
          <span className="text-[11px] text-slate-500 block mt-1">
            Modern encryption standard
          </span>
        </div>

        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 md:col-span-2">
          <span className="text-xs text-slate-400 block mb-1">Cipher Suite</span>
          <span className="text-xs font-semibold font-mono text-slate-200 break-all">
            {ssl.cipherSuite || 'TLS_AES_256_GCM_SHA384'}
          </span>
          <span className="text-[11px] text-slate-500 block mt-1">
            Authenticated Encryption with Associated Data (AEAD)
          </span>
        </div>
      </div>

      {/* Detailed Cert Specs Grid */}
      <div className="rounded-xl border border-slate-800 bg-slate-900 overflow-hidden divide-y divide-slate-800">
        <div className="p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <span className="text-xs font-medium text-slate-400">Subject (Issued To)</span>
          <span className="text-xs font-mono font-medium text-white break-all">
            CN={ssl.subject?.commonName || hostname}
            {ssl.subject?.organization ? `, O=${ssl.subject.organization}` : ''}
          </span>
        </div>

        <div className="p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <span className="text-xs font-medium text-slate-400">Issuer (Certificate Authority)</span>
          <span className="text-xs font-mono font-medium text-white break-all">
            {ssl.issuer?.organization || ssl.issuer?.commonName || 'Let’s Encrypt / WebTrust CA'}
          </span>
        </div>

        <div className="p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <span className="text-xs font-medium text-slate-400">Validity Window</span>
          <span className="text-xs font-mono text-slate-300">
            {ssl.validFrom ? new Date(ssl.validFrom).toLocaleDateString() : 'N/A'} —{' '}
            {ssl.validTo ? new Date(ssl.validTo).toLocaleDateString() : 'N/A'}
          </span>
        </div>

        {ssl.serialNumber && (
          <div className="p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <span className="text-xs font-medium text-slate-400">Serial Number</span>
            <span className="text-xs font-mono text-slate-400 break-all">
              {ssl.serialNumber}
            </span>
          </div>
        )}

        {ssl.fingerprint256 && (
          <div className="p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <span className="text-xs font-medium text-slate-400">SHA-256 Fingerprint</span>
            <span className="text-xs font-mono text-slate-400 break-all text-[11px]">
              {ssl.fingerprint256}
            </span>
          </div>
        )}

        {/* Subject Alternative Names (SANs) */}
        {ssl.subjectAltNames && ssl.subjectAltNames.length > 0 && (
          <div className="p-4 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-slate-400">
                Subject Alternative Names ({ssl.subjectAltNames.length})
              </span>
            </div>
            <div className="flex flex-wrap gap-1.5 max-h-32 overflow-y-auto">
              {ssl.subjectAltNames.map((san) => (
                <span
                  key={san}
                  className="px-2 py-0.5 rounded bg-slate-800 text-[11px] font-mono text-slate-300 border border-slate-700"
                >
                  {san}
                </span>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
