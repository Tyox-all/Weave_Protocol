# GitHub Setup Instructions

## Quick Start

### 1. Extract the Package

```bash
unzip weave-security-complete.zip
cd mund-mcp
```

### 2. Initialize Git Repository

```bash
git init
git add .
git commit -m "Initial commit: Weave Security Suite (Mund + Hord + Dōmere)"
```

### 3. Create GitHub Repository

Option A: **GitHub CLI**
```bash
gh repo create weave-security --public --source=. --push
```

Option B: **Manual**
1. Go to https://github.com/new
2. Name: `weave-security`
3. Description: `Vendor-neutral security for AI agents. Thread identity, intent verification, blockchain anchoring.`
4. Public
5. Don't initialize with README (we have one)
6. Create repository

Then:
```bash
git remote add origin https://github.com/YOUR_USERNAME/weave-security.git
git branch -M main
git push -u origin main
```

### 4. Verify Structure

Your repo should look like:
```
weave-security/
├── README.md           # Main documentation
├── LICENSE             # MIT
├── CONTRIBUTING.md
├── SECURITY.md
├── package.json        # Root (Mund)
├── src/                # Mund source
├── hord/               # Hord module
│   ├── src/
│   └── package.json
├── domere/             # Dōmere module
│   ├── src/
│   └── package.json
└── contracts/          # Smart contracts
    ├── solana/
    └── ethereum/
```

### 5. Add Topics/Tags

On GitHub repo page → Settings → Topics:
- ai-security
- mcp
- blockchain
- solana
- ethereum
- ai-agents
- security
- intent-verification
- open-source

### 6. Create Releases

```bash
# Tag version
git tag -a v1.0.0 -m "Initial release: Mund, Hord, Dōmere"
git push origin v1.0.0
```

Then on GitHub: Releases → Create release from tag → Add release notes

### 7. NPM Publishing (Optional)

If you want to publish to npm:

```bash
# Login to npm
npm login

# Publish Mund (root)
npm publish --access public

# Publish Hord
cd hord && npm publish --access public

# Publish Dōmere
cd ../domere && npm publish --access public
```

Package names in package.json:
- `@weave-security/mund`
- `@weave-security/hord`
- `@weave-security/domere`

Note: You'll need to create the `@weave-security` npm organization first.

### 8. Enable GitHub Actions (CI)

Create `.github/workflows/ci.yml`:
```yaml
name: CI
on: [push, pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - run: npm install
      - run: npm run build
      - run: cd hord && npm install && npm run build
      - run: cd domere && npm install && npm run build
```

### 9. Add Badges to README

```markdown
![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Node](https://img.shields.io/badge/node-%3E%3D18-brightgreen)
[![GitHub stars](https://img.shields.io/github/stars/YOUR_USERNAME/weave-security)](https://github.com/YOUR_USERNAME/weave-security/stargazers)
```

## Repository Settings Checklist

- [ ] Description added
- [ ] Topics added
- [ ] License visible (MIT)
- [ ] Issues enabled
- [ ] Discussions enabled (optional)
- [ ] Wiki disabled (use README instead)
- [ ] Releases created
- [ ] Branch protection on `main` (optional)

## Marketing Checklist

After pushing:
- [ ] Post to Reddit (r/MachineLearning, r/LocalLLaMA, r/Entrepreneur)
- [ ] Post to LinkedIn
- [ ] Post to Twitter/X
- [ ] Submit to Hacker News
- [ ] Add to MCP server directory (if exists)
- [ ] Create demo video
- [ ] Write blog post explaining architecture

## Questions?

The repo is self-contained. Each module (Mund, Hord, Dōmere) can be used independently or together.

Smart contracts in `/contracts` need separate deployment to Solana/Ethereum.
