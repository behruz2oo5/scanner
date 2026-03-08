# 🤖 Kali File-Reader Telegram Bot

A Python-based Telegram bot that lets you browse and read files on your **Kali Linux** machine directly from Telegram chat. Secured by an admin whitelist so only you can use it.

---

## 📦 Project Structure

```
kali-telegram-bot/
├── bot.py            # Main bot logic & all command handlers
├── config.py         # Loads settings from .env
├── requirements.txt  # Python dependencies
├── .env.example      # Environment variable template
└── README.md         # This file
```

---

## 🚀 Setup (on your Kali machine)

### 1. Prerequisites

```bash
sudo apt update
sudo apt install python3 python3-pip -y
```

### 2. Clone / copy the project

Copy the `kali-telegram-bot/` folder to your Kali machine, for example into your home directory:

```bash
cd ~
# copy the folder here
```

### 3. Install dependencies

```bash
cd kali-telegram-bot
pip3 install -r requirements.txt
```

### 4. Create your `.env` file

```bash
cp .env.example .env
nano .env
```

Fill in the values:

| Variable | Description |
|---|---|
| `BOT_TOKEN` | Token from **@BotFather** on Telegram |
| `ADMIN_IDS` | Your Telegram user ID(s), comma-separated |
| `ALLOWED_ROOT` | Directory the bot can browse (e.g. `/home/kali`) |

> **Tip — Find your Telegram ID:** Message **@userinfobot** on Telegram and it will reply with your numeric user ID.

### 5. Run the bot

```bash
python3 bot.py
```

You should see:
```
Bot started. Press Ctrl+C to stop.
```

---

## 💬 Commands

| Command | Description |
|---|---|
| `/start` | Welcome message |
| `/help` | List all commands |
| `/pwd` | Show the allowed root directory |
| `/ls [path]` | List directory contents |
| `/cat <path>` | Read & display a text file |
| `/download <path>` | Send a file as a Telegram document |

### Examples

```
/ls /home/kali
/ls /etc
/cat /etc/hostname
/cat /home/kali/.bashrc
/download /home/kali/notes.txt
```

---

## 🔒 Security

- **Admin whitelist** — only users in `ADMIN_IDS` can use the bot. Everyone else gets `⛔ Unauthorized.`
- **Path validation** — all paths are resolved with `Path.resolve()` and checked against `ALLOWED_ROOT`. `../` traversal attempts are blocked.
- **File size limits** — `/cat` refuses files > 5 MB; `/download` refuses files > 50 MB.

---

## 🔄 Run as a Background Service (optional)

To keep the bot running after you close your terminal:

```bash
# Using screen
screen -S telebot
python3 bot.py
# Press Ctrl+A then D to detach

# Or using nohup
nohup python3 bot.py &> bot.log &
```

---

## 🐛 Troubleshooting

| Problem | Fix |
|---|---|
| `BOT_TOKEN is not set` | Make sure `.env` exists and has `BOT_TOKEN=...` |
| Bot doesn't respond | Check `ADMIN_IDS` contains your correct Telegram user ID |
| `Permission denied` | Run with `sudo` or change `ALLOWED_ROOT` to a path you own |
| Module not found | Run `pip3 install -r requirements.txt` again |

# scanner
