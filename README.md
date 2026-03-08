# 🤖 Kali CyberSec Telegram Bot (All-in-One)

A powerful, single-file Telegram bot designed for **Kali Linux** that automates common cybersecurity reconnaissance tasks. Browse directories, scan ports, discover subdomains, fingerprint technologies, and take screenshots—all directly from your Telegram chat.

---

## � Features

- **Port Scanning**: Resolve hostnames and scan the top 18 most common ports.
- **Subdomain Discovery**: Integrated with `subfinder` and `assetfinder`.
- **Directory Brute-forcing**: High-speed discovery using `feroxbuster` with dynamic wordlist selection (WordPress-aware).
- **Technology Fingerprinting**: Identify web stacks using `whatweb`.
- **Automated Screenshots**: Capture visual evidence using `gowitness`.
- **Data Persistence**: All results are saved to a local SQLite database (`recon_results.db`).
- **Security**: Built-in admin whitelist to ensure only you can control the bot.

---

## � Prerequisites

This bot is designed to run on **Kali Linux**. Ensure you have the following tools installed:

### 1. System Tools
```bash
sudo apt update
sudo apt install nmap whatweb feroxbuster seclists -y
```

### 2. Go-based Tools
```bash
# Subdomain discovery
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/tomnomnom/assetfinder@latest

# Screenshots
go install github.com/sensepost/gowitness@latest
```

---

## 📦 Installation

1. **Clone the repository** (or copy `bot.py`):
   ```bash
   mkdir kali-bot && cd kali-bot
   ```

2. **Install Python dependencies**:
   ```bash
   pip install python-telegram-bot python-dotenv
   ```

3. **Set up environment variables**:
   Create a `.env` file in the same directory:
   ```env
   BOT_TOKEN=your_telegram_bot_token
   ADMIN_IDS=your_numeric_telegram_id
   ```
   > [!TIP]
   > Get your `BOT_TOKEN` from [@BotFather](https://t.me/BotFather) and your `ADMIN_IDS` from [@userinfobot](https://t.me/userinfobot).

---

## 🕹 Usage

Run the bot:
```bash
python3 bot.py
```

### Available Commands

| Command | Action |
|:--- |:--- |
| `/start` | Welcome message |
| `/help` | Detailed command list |
| `/scan <target>` | Quick port scan for 18 common services |
| `/recon <target>` | **Full Pipeline**: Subdomains → Ports → Tech → Dirs → Screenshot |
| `/ferox <url>` | Dedicated directory brute-force |
| `/history` | View scan history from the current session |

---

## 🔒 Security & Disclaimer

- **Admin Only**: Unauthorized users are blocked automatically via the `ADMIN_IDS` whitelist.
- **Path Traversal**: Protected against `../` attacks (for future file reading features).
- **Ethical Use**: This tool is for **authorized security testing only**. Never use it on targets you do not have permission to scan.

---

Built with ❤️ for the security community.
