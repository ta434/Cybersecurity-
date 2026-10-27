import React from 'react';
import { SecurityGrade, CategoryScores } from '../types/security';
import { ShieldCheck, ShieldAlert, ShieldX } from 'lucide-react';

interface ScoreGaugeProps {
  scores: CategoryScores;
  size?: 'sm' | 'md' | 'lg';
}

export const ScoreGauge: React.FC<ScoreGaugeProps> = ({ scores }) => {
  const { grade, overallScore, sslScore, headersScore, dnsEmailScore, cookieScore, infrastructureScore, sqliScore } = scores;

  // Grade color theme for dark background
  const getGradeTheme = (g: SecurityGrade) => {
    switch (g) {
      case 'A+':
      case 'A':
        return {
          textColor: 'text-emerald-400',
          borderColor: 'border-emerald-500/30',
          ringColor: '#10b981',
          label: 'Strong Security Posture',
          icon: ShieldCheck,
        };
      case 'B':
        return {
          textColor: 'text-sky-400',
          borderColor: 'border-sky-500/30',
          ringColor: '#38bdf8',
          label: 'Adequate Security Posture',
          icon: ShieldCheck,
        };
      case 'C':
        return {
          textColor: 'text-amber-400',
          borderColor: 'border-amber-500/30',
          ringColor: '#f59e0b',
          label: 'Needs Hardening',
          icon: ShieldAlert,
        };
      case 'D':
      case 'F':
      default:
        return {
          textColor: 'text-rose-400',
          borderColor: 'border-rose-500/30',
          ringColor: '#f43f5e',
          label: 'Critical Vulnerabilities',
          icon: ShieldX,
        };
    }
  };

  const theme = getGradeTheme(grade);
  const StatusIcon = theme.icon;

  // SVG Circular math
  const radius = 54;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (overallScore / 100) * circumference;

  const categories = [
    { label: 'SSL / TLS Certificate', score: sslScore, weight: '20%' },
    { label: 'HTTP Security Headers', score: headersScore, weight: '20%' },
    { label: 'SQLi & Query Defense', score: sqliScore ?? 100, weight: '20%' },
    { label: 'DNS & Email Defense', score: dnsEmailScore, weight: '15%' },
    { label: 'Cookie Privacy & Flags', score: cookieScore, weight: '15%' },
    { label: 'Host & HTTPS Redirects', score: infrastructureScore, weight: '10%' },
  ];

  return (
    <div className="flex flex-col lg:flex-row items-center gap-8 p-6 bg-slate-900 border border-slate-800 rounded-xl shadow-lg font-serif">
      {/* Grade Ring */}
      <div className="relative flex flex-col items-center justify-center shrink-0">
        <svg className="w-36 h-36 transform -rotate-90" viewBox="0 0 128 128">
          {/* Background track */}
          <circle
            cx="64"
            cy="64"
            r={radius}
            stroke="#1e293b"
            strokeWidth="9"
            fill="transparent"
          />
          {/* Animated score stroke */}
          <circle
            cx="64"
            cy="64"
            r={radius}
            stroke={theme.ringColor}
            strokeWidth="9"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            fill="transparent"
            className="transition-all duration-700 ease-out"
          />
        </svg>

        <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
          <span className={`text-4xl font-extrabold tracking-tight ${theme.textColor} font-serif`}>
            {grade}
          </span>
          <span className="text-xs text-slate-400 font-mono tabular-nums mt-0.5">
            {overallScore}<span className="text-slate-500">/100</span>
          </span>
        </div>
      </div>

      {/* Category Breakdown Bars */}
      <div className="w-full flex-1 space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <StatusIcon className={`w-4 h-4 ${theme.textColor}`} />
            <span className="text-sm font-semibold text-white font-serif">Overall Security Score</span>
          </div>
          <span className={`text-xs font-mono font-medium ${theme.textColor}`}>
            {theme.label}
          </span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 pt-1">
          {categories.map((cat) => {
            const barColor =
              cat.score >= 80 ? 'bg-emerald-500' : cat.score >= 60 ? 'bg-amber-500' : 'bg-rose-500';
            return (
              <div key={cat.label} className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
                <div className="flex items-center justify-between text-xs mb-1.5 font-serif">
                  <span className="text-slate-300 font-medium truncate max-w-[170px]" title={cat.label}>
                    {cat.label}
                  </span>
                  <div className="flex items-center gap-1.5 font-mono">
                    <span className="text-slate-500 text-[11px]">({cat.weight})</span>
                    <span className="text-white font-semibold tabular-nums">{cat.score}%</span>
                  </div>
                </div>
                <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
                  <div
                    className={`h-full ${barColor} rounded-full transition-all duration-700 ease-out`}
                    style={{ width: `${Math.max(4, cat.score)}%` }}
                  />
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
