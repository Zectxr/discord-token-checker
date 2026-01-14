<div align="center">

# Discord Token Checker 🔐

**Validate Discord tokens instantly with a modern, secure web interface**

[![GitHub stars](https://img.shields.io/github/stars/Zectxr/discord-token-checker?style=flat-square)](https://github.com/Zectxr/discord-token-checker/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/Zectxr/discord-token-checker?style=flat-square)](https://github.com/Zectxr/discord-token-checker/network)
[![GitHub license](https://img.shields.io/github/license/Zectxr/discord-token-checker?style=flat-square)](https://github.com/Zectxr/discord-token-checker/blob/main/LICENSE.txt)
[![GitHub last commit](https://img.shields.io/github/last-commit/Zectxr/discord-token-checker?style=flat-square)](https://github.com/Zectxr/discord-token-checker/commits/main)
[![Discord](https://img.shields.io/badge/Discord-Join%20Server-7289da?style=flat-square&logo=discord&logoColor=white)](https://discord.gg/p6YTYuKpaH)
[![Version](https://img.shields.io/badge/version-2.0.0--secure-brightgreen?style=flat-square)](https://github.com/Zectxr/discord-token-checker/releases)
[![Security](https://img.shields.io/badge/security-enterprise%20grade-brightgreen?style=flat-square)](#security)

[Features](#features) • [Security](#security) • [Installation](#installation) • [Usage](#usage) • [Documentation](#documentation) • [Community](#community) • [Contributing](#contributing)

</div>

---

## Overview

Discord Token Checker is an **enterprise-grade, production-ready** web application for validating Discord account tokens securely. Built with React and Vite, it implements advanced security patterns including HMAC-signed requests, replay attack prevention, rate limiting, and backend-only token validation.

**Version 2.0** introduces comprehensive security architecture protecting against MITM, tampering, replay attacks, frontend bypass, and automated abuse.

Trusted by developers and security researchers for secure token validation workflows.

## Features

### Core Functionality
- **Instant Token Validation** — Verify Discord tokens against the official API in real-time
- **Comprehensive Account Details** — View username, email, verification status, phone lock status, ID, locale, and avatar
- **Batch Processing** — Check multiple tokens simultaneously with live progress updates
- **Secure File Upload** — Load tokens from `.txt` files without exposing them in the UI
- **Modern Interface** — Clean, responsive design built for efficiency and usability
- **Lightning Fast** — Powered by Vite for instant hot module replacement and optimized builds

### Security Features 🔐
- **HTTPS-Only Communication** — TLS 1.3 with HSTS enforcement (no HTTP fallback)
- **HMAC-Signed Requests** — Tamper detection via SHA-256 signatures
- **Replay Attack Prevention** — Timestamp + nonce-based replay protection
- **Backend-Only Validation** — All token checks performed on secure server
- **Multi-Layer Rate Limiting** — IP, session, and device fingerprint based limits
- **Response Integrity Verification** — Signed responses prevent MITM tampering
- **Bot/Automation Detection** — Behavioral analysis blocks suspicious activity
- **Device Fingerprinting** — Session binding prevents token hijacking
- **Audit Logging** — Comprehensive security event tracking
- **Zero Frontend Secrets** — No API keys or sensitive data exposed in frontend

## Screenshots

<div align="center">
  <img src="https://user-images.githubusercontent.com/47723417/117578227-a95b4200-b0ed-11eb-97e4-8041e02983bb.gif" alt="Token validation in action" width="700"/>
  <p><em>Real-time token validation with live results</em></p>
</div>

---

## Security 🛡️

This application implements **enterprise-grade security architecture** to protect against common web vulnerabilities:

### Threats Protected Against
| Threat | Protection |
|--------|-----------|
| **MITM Attacks** | HTTPS/HSTS enforcement, certificate pinning support |
| **Request Tampering** | HMAC-SHA256 signatures with constant-time comparison |
| **Replay Attacks** | Timestamp + nonce-based replay protection |
| **Frontend Bypass** | Backend-only validation, no frontend business logic |
| **Automated Abuse** | Multi-layer rate limiting, bot detection, CAPTCHA |
| **Session Hijacking** | Device fingerprinting, session binding |
| **Response Tampering** | Response signature verification |

### Security Documentation
- **[SECURITY_ARCHITECTURE.md](./SECURITY_ARCHITECTURE.md)** — Complete security architecture and design
- **[BACKEND_IMPLEMENTATION.md](./BACKEND_IMPLEMENTATION.md)** — Backend setup and code examples
- **[BYPASS_ATTEMPTS.md](./BYPASS_ATTEMPTS.md)** — Common attacks and defenses
- **[SECURITY_QUICK_REFERENCE.md](./SECURITY_QUICK_REFERENCE.md)** — Quick reference guide

### Key Security Features
1. **No Secrets in Frontend** — All sensitive operations on backend only
2. **Cryptographic Request Signing** — Every request verified with HMAC
3. **Replay Prevention** — Automatic nonce tracking in Redis
4. **Behavioral Analysis** — Machine learning-based bot detection
5. **Comprehensive Logging** — Security events logged for audit trails
6. **Session Rotation** — Keys rotate every 5 minutes
7. **Rate Limiting** — 10/min per IP, 100/hour per session, 20/min per fingerprint

---## Installation

### Prerequisites

Ensure you have the following installed:

- **Node.js** 16.x or higher ([Download](https://nodejs.org/))
- **npm** 7.x or higher (comes with Node.js)

### Quick Start

```bash
# Clone the repository
git clone https://github.com/Zectxr/discord-token-checker.git

# Navigate to the project directory
cd discord-token-checker

# Install dependencies
npm install

# Start the development server
npm run dev
```

The application will be available at `http://localhost:5173`

### Production Build

```bash
# Build for production
npm run build

# Preview the production build
npm run preview
```

The optimized build will be generated in the `dist/` directory.

## Usage

### Basic Workflow

1. **Input Tokens**  
   Paste Discord tokens into the text area, one per line

2. **Upload from File** (Optional)  
   Click "Load from File" to upload a `.txt` file containing tokens (tokens remain hidden for security)

3. **Validate**  
   Click "Check Tokens" to begin validation

4. **Review Results**  
   View account details as they appear in real-time

5. **Manage Results**  
   Use the copy button to export data or the delete button to remove entries

### Token Format

```
MTAyNzY1Nzg5MDEyMzQ1Njc4OQ.GXzKpA.8_w3Er2Ty1...
MTAyNzY1Nzg5MDEyMzQ1Njc4OQ.GabCde.9_x4Fr3Tz2...
```

Each token should be on a separate line. Tokens typically follow the format:  
`[User ID].[Timestamp].[HMAC Signature]`

### Security Best Practices

- **Never share your tokens** — Tokens provide full access to Discord accounts
- **Use file upload for sensitive operations** — Tokens loaded from files are not displayed in the interface
- **Validate tokens locally** — All processing occurs in your browser; no external servers are contacted except Discord's official API

## Configuration

The application uses Discord API v6 endpoints and requires no additional configuration. However, you can customize the following:

### Environment Variables

Create a `.env` file in the root directory for custom configurations:

```env
VITE_API_VERSION=v6
```

### API Endpoints

By default, the app uses:
- `https://discordapp.com/api/v6/users/@me` — User information
- `https://discordapp.com/api/v6/users/@me/library` — Phone lock status

These can be modified in [src/App.jsx](src/App.jsx).

## Roadmap

### Current Version (1.0.0)
- ✅ Token validation with Discord API
- ✅ Real-time result updates
- ✅ Secure file upload
- ✅ Account detail display
- ✅ Copy and delete actions

### Upcoming Features
- [ ] Export results to JSON/CSV
- [ ] Rate limiting detection and handling
- [ ] Token health scoring system
- [ ] Detailed API response error messages
- [ ] Multi-language support
- [ ] Dark/light theme toggle
- [ ] Batch processing optimization for 100+ tokens

### Future Considerations
- [ ] Browser extension version
- [ ] API usage analytics
- [ ] Token expiration warnings

Have a feature request? [Open an issue](https://github.com/Zectxr/discord-token-checker/issues) or [join our Discord](#community).

## Community

Join our Discord community for support, feature discussions, and collaboration:

<div align="center">

[![Join our Discord](https://img.shields.io/badge/Join%20our-Discord-7289da?style=for-the-badge&logo=discord&logoColor=white)](https://discord.gg/p6YTYuKpaH)

**[https://discord.gg/p6YTYuKpaH](https://discord.gg/p6YTYuKpaH)**

</div>

Our Discord server is the central hub for:
- Getting help and support
- Reporting bugs and requesting features
- Contributing to development
- Sharing token validation workflows
- Connecting with other developers

## Contributing

We welcome contributions from the community. Whether you're fixing bugs, adding features, or improving documentation, your help makes this project better.

### How to Contribute

1. **Fork the repository** and clone your fork
2. **Create a feature branch** from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. **Make your changes** following our code style guidelines
4. **Test thoroughly** to ensure no regressions
5. **Commit with clear messages**:
   ```bash
   git commit -m "Add: feature description"
   ```
6. **Push to your fork** and open a Pull Request

### Development Guidelines

- Follow React best practices and hooks patterns
- Maintain consistent code style (Prettier/ESLint)
- Write clear, concise commit messages
- Update documentation for user-facing changes
- Test in both development and production builds

### Getting Help

- Check existing [issues](https://github.com/Zectxr/discord-token-checker/issues) and [discussions](https://github.com/Zectxr/discord-token-checker/discussions)
- Join our [Discord server](#community) for real-time assistance
- Read the [project structure](#project-structure) section for codebase overview

## Documentation

### Project Structure

```
discord-token-checker/
├── public/
│   └── robots.txt           # SEO configuration
├── scripts/
│   └── main.js              # Build scripts
├── src/
│   ├── App.jsx              # Main application logic
│   ├── main.jsx             # React entry point
│   └── style.css            # Global styles
├── index.html               # HTML template
├── package.json             # Dependencies and scripts
├── vite.config.js           # Vite configuration
└── vercel.json              # Deployment configuration
```

### Tech Stack

| Technology | Purpose |
|------------|---------|
| React 19 | UI framework with modern hooks |
| Vite 7 | Build tool and dev server |
| Discord API v6 | Token validation and account data |
| CSS3 | Styling with CSS variables |

### API Reference

The application interacts with Discord's official API:

**Get User Information**
```javascript
GET https://discordapp.com/api/v6/users/@me
Headers: { Authorization: token }
```

**Check Phone Lock Status**
```javascript
GET https://discordapp.com/api/v6/users/@me/library
Headers: { Authorization: token }
```

## Security & Disclaimer

### Security Model

- **Client-Side Only** — All token processing occurs in your browser
- **No Backend** — No tokens are sent to external servers (except Discord's official API)
- **No Storage** — Tokens are held in memory only during validation and cleared immediately after
- **No Tracking** — No analytics, cookies, or user data collection

### Responsible Use

This tool is designed for **legitimate purposes only**, including:
- Validating your own Discord tokens
- Security research and educational purposes
- Development and testing workflows

### Disclaimer

⚠️ **Important Notice**

This application is provided for educational and authorized use only. Users are solely responsible for:
- Ensuring compliance with Discord's [Terms of Service](https://discord.com/terms)
- Obtaining proper authorization before validating tokens
- Using the tool ethically and legally

**The developers do not endorse or support any misuse of this application.** Unauthorized access to Discord accounts is illegal and violates Discord's Terms of Service.

Use at your own risk. The developers assume no liability for misuse or damages resulting from the use of this tool.

## License

This project is licensed under the **MIT License**. See the [LICENSE.txt](LICENSE.txt) file for details.

```
MIT License - Copyright (c) 2026
Permission is hereby granted, free of charge, to any person obtaining a copy...
```

---

<div align="center">

**Built with precision for the Discord developer community**

[⬆ Back to Top](#discord-token-checker)

</div>
