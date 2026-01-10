# tokencord

Discord token checker built with React and Vite. Validates multiple tokens, surfaces account details, and keeps sensitive values hidden by default.

## Overview

tokencord is a client-side web application for quickly verifying Discord tokens. It processes tokens in the browser, calls the Discord API directly, and presents validation results with associated account metadata.

## Features

- Multi-token input (one per line) with incremental validation
- File upload for bulk token checks without exposing token values in the UI
- Account detail display: tag, ID, email, verification status, locale, phone, phone-lock status, and avatar
- Copy-to-clipboard for individual results; delete results inline
- Real-time valid/invalid counters and responsive layout
- Client-side only: no token storage or server-side relay

## Live Site

- Production: https://tokencords.vercel.app/

## Installation

Prerequisites: Node.js 16+ and npm.

```bash
git clone https://github.com/Zectxr/discord-token-checker.git
cd discord-token-checker
npm install
npm run dev
```

Visit http://localhost:5173 during development.

### Build and Preview

```bash
npm run build
npm run preview
```

## Usage

1. Paste tokens into the textarea, one per line, or load a `.txt` file (tokens stay hidden when loaded from file).
2. Select "Check Tokens" to validate.
3. Review per-token cards for validity, account details, copy, and delete actions.

Token format example:

```
MXXXXXXXXXXXXXXXXXXXXXXX.XXXXXX.XXXXXXXXXXXXXXXXXXXXXXXXXX
```

## Security and Privacy

- Tokens are handled in-memory on the client and are not persisted.
- Calls are made directly to the Discord API; no intermediary services are used.
- No analytics or tracking is included.

## Tech Stack

- React 18
- Vite
- Vanilla CSS with custom properties
- Discord API v6

## Project Structure

```
discord-token-checker/
├── src/
│   ├── App.jsx          # Main application component
│   ├── main.jsx         # React entry point
│   └── style.css        # Styles
├── scripts/             # Non-React script variant
├── public/              # Static assets (robots.txt, icons)
├── index.html           # HTML template
├── vite.config.js       # Vite configuration
└── package.json
```

## Development Guidelines

- Follow React best practices and keep components cohesive.
- Maintain consistent formatting and naming conventions.
- Add tests or checks where practical for new functionality.
- Update documentation when behavior changes.

## Deployment

- The project is Vercel-ready; `npm run build` produces the production bundle.
- Ensure environment settings (if any) are configured in Vercel before deploy.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Disclaimer

Use this tool only for lawful and authorized purposes. Ensure compliance with Discord's Terms of Service and all applicable laws.

## Support

- Issues: https://github.com/Zectxr/discord-token-checker/issues
- Discussions and suggestions: https://github.com/Zectxr/discord-token-checker/discussions
