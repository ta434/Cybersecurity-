import express, { Request, Response } from 'express';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { runSecurityAnalysis, SAMPLE_DOMAINS } from './src/services/analyzer';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;
const isProd = process.env.NODE_ENV === 'production';

app.use(express.json());

// Sample domains route (supports both /api/sample-domains and /sample-domains)
app.get(['/api/sample-domains', '/sample-domains'], (_req: Request, res: Response) => {
  res.json({ samples: SAMPLE_DOMAINS });
});

// Main Analysis Endpoint (supports both /api/analyze and /analyze)
app.post(['/api/analyze', '/analyze'], async (req: Request, res: Response) => {
  const rawUrl = (req.body?.url || '').trim();

  if (!rawUrl) {
    return res.status(400).json({ error: 'URL is required' });
  }

  try {
    const report = await runSecurityAnalysis(rawUrl);
    return res.json(report);
  } catch (err: any) {
    console.error('[Analyze Endpoint Error]:', err);
    return res.status(400).json({
      error: err.message || 'An unexpected error occurred while analyzing the target domain',
    });
  }
});

// Setup Vite dev server or production static serving
async function setupServer() {
  if (!isProd) {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve(__dirname, 'dist');
    if (fs.existsSync(distPath)) {
      app.use(express.static(distPath));
      app.get('*', (_req, res) => {
        res.sendFile(path.resolve(distPath, 'index.html'));
      });
    }
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[CyberScan Server] Running on http://0.0.0.0:${PORT}`);
  });
}

export default app;

if (!process.env.VERCEL) {
  setupServer().catch((err) => {
    console.error('[CyberScan Server] Startup error:', err);
  });
}
