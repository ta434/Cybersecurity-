import type { IncomingMessage, ServerResponse } from 'node:http';
import { runSecurityAnalysis } from '../src/services/analyzer';

// Safe body parser that never hangs, supporting pre-parsed bodies, string bodies, streams, or query params
function getRequestBody(req: any): Promise<any> {
  return new Promise((resolve) => {
    // 1. If body already parsed as object by Vercel
    if (req.body && typeof req.body === 'object') {
      return resolve(req.body);
    }

    // 2. If body is a string
    if (typeof req.body === 'string') {
      try {
        return resolve(JSON.parse(req.body));
      } catch {
        return resolve({ url: req.body });
      }
    }

    // 3. If stream has already ended or not readable, don't wait on events
    if (req.readableEnded || req.complete || typeof req.on !== 'function') {
      return resolve({});
    }

    // 4. Read stream with strict safety timeout (500ms max)
    let raw = '';
    const safetyTimer = setTimeout(() => {
      resolve({});
    }, 500);

    req.on('data', (chunk: any) => {
      raw += chunk;
      if (raw.length > 524288) { // 512KB limit
        clearTimeout(safetyTimer);
        resolve({});
      }
    });

    req.on('end', () => {
      clearTimeout(safetyTimer);
      if (!raw) return resolve({});
      try {
        resolve(JSON.parse(raw));
      } catch {
        resolve({ url: raw.trim() });
      }
    });

    req.on('error', () => {
      clearTimeout(safetyTimer);
      resolve({});
    });
  });
}

export default async function handler(
  req: IncomingMessage & { body?: any; query?: any; url?: string },
  res: ServerResponse & { status?: (code: number) => any; json?: (data: any) => void }
) {
  // CORS & Security headers
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,POST');
  res.setHeader(
    'Access-Control-Allow-Headers',
    'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version'
  );

  if (req.method === 'OPTIONS') {
    res.statusCode = 200;
    res.end();
    return;
  }

  try {
    const body = await getRequestBody(req);

    // Extract URL from body or query parameters (supports both POST and GET)
    let rawUrl = (body?.url || '').trim();
    if (!rawUrl && req.url) {
      try {
        const parsed = new URL(req.url, 'http://localhost');
        rawUrl = (parsed.searchParams.get('url') || '').trim();
      } catch {}
    }
    if (!rawUrl && req.query?.url) {
      rawUrl = String(req.query.url).trim();
    }

    if (!rawUrl) {
      res.statusCode = 400;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ error: 'Please enter a target URL or domain to analyze (e.g. github.com)' }));
      return;
    }

    const report = await runSecurityAnalysis(rawUrl);
    res.statusCode = 200;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify(report));
  } catch (err: any) {
    console.error('[API Analyze Error]:', err);
    res.statusCode = 200; // Return 200 with fallback diagnostic report or error payload
    res.setHeader('Content-Type', 'application/json');
    res.end(
      JSON.stringify({
        error: err?.message || 'Security analysis could not complete for the specified domain.',
        targetUrl: req.url || '',
      })
    );
  }
}
