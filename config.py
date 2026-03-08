import os
from dotenv import load_dotenv

load_dotenv()

# -- Telegram Bot Token from @BotFather --
BOT_TOKEN: str = os.getenv("BOT_TOKEN", "")

# -- Authorized Telegram chat IDs (comma-separated in .env) --
_raw_ids = os.getenv("ADMIN_IDS", "")
ADMIN_IDS: set[int] = {int(i.strip()) for i in _raw_ids.split(",") if i.strip()}

if not BOT_TOKEN:
    raise ValueError("BOT_TOKEN is not set. Copy .env.example to .env and fill in your token.")

