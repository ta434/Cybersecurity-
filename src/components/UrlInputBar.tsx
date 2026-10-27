import React, { useState } from 'react';
import { Search, Loader2, X, Globe } from 'lucide-react';

interface UrlInputBarProps {
  onAnalyze: (url: string) => void;
  isLoading: boolean;
  initialUrl?: string;
  autoFocus?: boolean;
}

export const UrlInputBar: React.FC<UrlInputBarProps> = ({
  onAnalyze,
  isLoading,
  initialUrl = '',
  autoFocus = false,
}) => {
  const [url, setUrl] = useState(initialUrl);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (url.trim() && !isLoading) {
      onAnalyze(url.trim());
    }
  };

  return (
    <div className="w-full max-w-3xl mx-auto">
      {/* Scanner Bar */}
      <form onSubmit={handleSubmit} className="relative">
        <div className="relative flex items-center bg-slate-900 border border-slate-800 rounded-xl shadow-xl focus-within:border-slate-600 focus-within:ring-2 focus-within:ring-slate-700/40 transition-all">
          <div className="pl-4 pr-2 text-slate-400 flex items-center gap-1.5 shrink-0">
            <Globe className="w-4 h-4 text-slate-400" />
            <span className="text-xs font-mono text-slate-500 select-none">https://</span>
          </div>

          <input
            type="text"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="Enter URL to analyze (e.g., github.com)..."
            disabled={isLoading}
            autoFocus={autoFocus}
            className="w-full py-4 pr-10 text-base font-serif bg-transparent text-white placeholder-slate-500 focus:outline-none"
          />

          {url && !isLoading && (
            <button
              type="button"
              onClick={() => setUrl('')}
              className="p-1.5 mr-2 text-slate-400 hover:text-white rounded-md hover:bg-slate-800 transition-colors"
              aria-label="Clear input"
            >
              <X className="w-4 h-4" />
            </button>
          )}

          <div className="pr-2">
            <button
              type="submit"
              disabled={isLoading || !url.trim()}
              className="flex items-center gap-2 px-6 py-2.5 text-sm font-serif font-bold text-slate-950 bg-white hover:bg-slate-200 disabled:opacity-50 disabled:cursor-not-allowed rounded-lg shadow-xs transition-all whitespace-nowrap"
            >
              {isLoading ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin text-slate-950" />
                  <span>Scanning...</span>
                </>
              ) : (
                <>
                  <Search className="w-4 h-4 text-slate-950" />
                  <span>Scan URL</span>
                </>
              )}
            </button>
          </div>
        </div>
      </form>
    </div>
  );
};
