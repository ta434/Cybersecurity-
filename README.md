# CyberScan — Domain & URL Security Posture Analyzer

CyberScan is a full-stack cybersecurity auditing engine that evaluates domain certificates, HTTP security headers, DNS authentication records, cookie privacy compliance, server infrastructure, heuristic threat indicators, and SQL injection defenses.

## 🚀 Quick Start (Run Locally)

### Prerequisites
- Node.js 18+ or Bun
- npm, pnpm, yarn, or bun

### 1. Install Dependencies
```bash
npm install
```

### 2. Start Development Server
```bash
npm run dev
```

Visit [http://localhost:3000](http://localhost:3000) in your browser.

---

## 📦 Pushing to GitHub

To push this repository to your GitHub account:

```bash
git remote set-url origin https://github.com/ta434/Cybersecurity-.git
git branch -M main
git push -u origin main
```

If prompted for credentials, enter your GitHub username and your **Personal Access Token (PAT)** as the password (generate one at [github.com/settings/tokens](https://github.com/settings/tokens) with `repo` scope).

---

## ⚡ Deployment on Vercel

This repository includes `vercel.json` and `/api/index.ts` ready for zero-config Vercel deployment:

1. Import your `ta434/Cybersecurity-` repository into [vercel.com](https://vercel.com).
2. Framework Preset: **Vite**.
3. Click **Deploy**.

---

## 🛠️ Tech Stack & Architecture
- **Frontend**: React 19, TypeScript, Tailwind CSS, Lucide Icons
- **Backend API**: Node.js Express, real TLS X.509 socket auditing, DNS resolver (A, AAAA, MX, TXT, CAA), HTTP security headers inspection, SQL injection heuristic checks
- **Build Tool**: Vite
