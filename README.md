# 🔍 Discord Token Checker

<div align="center">
  <img src="https://img.shields.io/badge/React-20232A?style=for-the-badge&logo=react&logoColor=61DAFB" alt="React" />
  <img src="https://img.shields.io/badge/Vite-646CFF?style=for-the-badge&logo=vite&logoColor=white" alt="Vite" />
  <img src="https://img.shields.io/badge/JavaScript-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black" alt="JavaScript" />
  <img src="https://img.shields.io/badge/Discord-5865F2?style=for-the-badge&logo=discord&logoColor=white" alt="Discord" />
  <br>
  <img src="https://img.shields.io/github/stars/xNaCly/tokenchecker-website?style=social" alt="GitHub stars" />
  <img src="https://img.shields.io/github/forks/xNaCly/tokenchecker-website?style=social" alt="GitHub forks" />
  <img src="https://img.shields.io/github/issues/xNaCly/tokenchecker-website" alt="GitHub issues" />
  <img src="https://img.shields.io/github/license/xNaCly/tokenchecker-website" alt="License" />
</div>

## ✨ Overview

**Discord Token Checker** is a modern, lightweight web application built with React that allows you to verify Discord account tokens and view detailed account information. Perfect for developers, security researchers, and Discord enthusiasts who need to validate tokens quickly and efficiently.

### 🚀 Key Features

- **🔐 Token Validation**: Instantly check if Discord tokens are valid or invalid
- **📊 Real-time Results**: See results appear one by one as tokens are processed
- **👤 Account Details**: View comprehensive account information including:
  - Username and discriminator
  - Email and verification status
  - Account ID and locale
  - Phone number and lock status
  - Profile avatar
- **📱 Responsive Design**: Beautiful, modern UI that works on all devices
- **⚡ Fast & Lightweight**: Built with Vite for lightning-fast performance
- **🔒 Secure**: Direct API calls to Discord with no data storage
- **📁 File Upload**: Load tokens from text files for bulk checking
- **🗑️ Easy Management**: Delete individual results with one click
- **📋 Copy to Clipboard**: Copy account data with a single button

## 📸 Screenshots

<div align="center">
  <img src="https://user-images.githubusercontent.com/47723417/117578227-a95b4200-b0ed-11eb-97e4-8041e02983bb.gif" alt="Discord Token Checker Demo" width="600"/>
</div>

## 🛠️ Installation

### Prerequisites
- Node.js (v16 or higher)
- npm or yarn

### Quick Start

1. **Clone the repository**
   ```bash
   git clone https://github.com/xNaCly/tokenchecker-website.git
   cd tokenchecker-website
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Start the development server**
   ```bash
   npm run dev
   ```

4. **Open your browser**
   ```
   http://localhost:5173
   ```

### Build for Production

```bash
npm run build
npm run preview
```

## 📖 Usage

1. **Enter Tokens**: Paste your Discord tokens in the text area, one per line
2. **Load from File**: Or upload a `.txt` file containing tokens
3. **Check Tokens**: Click the "Check Tokens" button
4. **View Results**: Watch as results appear in real-time
5. **Manage Results**: Copy account data or remove individual entries

### Token Format
```
YOUR_DISCORD_TOKEN_HERE
```

## 🏗️ Architecture

### Tech Stack
- **Frontend**: React 18 with Hooks
- **Build Tool**: Vite
- **Styling**: Modern CSS with CSS Variables
- **API**: Discord API v6 (direct integration)

### Project Structure
```
tokenchecker-website/
├── src/
│   ├── App.jsx          # Main application component
│   ├── main.jsx         # React entry point
│   └── style.css        # Application styles
├── public/
├── index.html           # HTML template
├── vite.config.js       # Vite configuration
└── package.json         # Dependencies and scripts
```

## 🔒 Security & Privacy

- **No Data Storage**: Tokens are processed in-memory only
- **Direct API Calls**: Communicates directly with Discord's API
- **Client-Side Only**: All processing happens in your browser
- **No Tracking**: No analytics or data collection

### Security Features
- Validates tokens against Discord's official API
- Checks for phone lock status
- Displays comprehensive account security information

## 🤝 Contributing

We welcome contributions! Please follow these steps:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Commit your changes: `git commit -m 'Add amazing feature'`
4. Push to the branch: `git push origin feature/amazing-feature`
5. Open a Pull Request

### Development Guidelines
- Follow React best practices
- Maintain the existing code style
- Add tests for new features
- Update documentation as needed

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is intended for educational and legitimate purposes only. Users are responsible for complying with Discord's Terms of Service and applicable laws. The developers are not responsible for any misuse of this application.

## 🙏 Acknowledgments

- Original concept by [xNaCly](https://github.com/xnacly)
- Built with ❤️ using React and Vite
- Discord API for account validation

## 📞 Support

- 🐛 Found a bug? [Open an issue](https://github.com/xNaCly/tokenchecker-website/issues)
- 💡 Have a suggestion? [Start a discussion](https://github.com/xNaCly/tokenchecker-website/discussions)
- ⭐ Show your support by starring this repo!

---

<div align="center">
  <p>Made with ❤️ for the Discord community</p>
  <p>
    <a href="https://github.com/xNaCly">GitHub</a> •
    <a href="https://discord.gg">Discord</a>
  </p>
</div>
