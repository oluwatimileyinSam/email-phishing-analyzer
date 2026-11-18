import json
import os
import urllib.error
import urllib.request

from dotenv import load_dotenv


def main():
    load_dotenv()
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
    if not token:
        print("Set TELEGRAM_BOT_TOKEN in the .env file first.")
        return

    request = urllib.request.Request("https://api.telegram.org/bot" + token + "/getUpdates")

    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            data = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        if error.code == 401:
            print("Telegram refused the bot token. Check TELEGRAM_BOT_TOKEN in the .env file.")
        else:
            print("Telegram returned code", error.code)
        return
    except (OSError, ValueError):
        print("Telegram could not be reached.")
        return

    chats = {}
    for update in data.get("result", []):
        message = update.get("message") or {}
        chat = message.get("chat") or {}
        if "id" in chat:
            chats[chat["id"]] = chat.get("type", "unknown")

    if not chats:
        print("No messages found. Open your bot in Telegram, press Start, send it a message, then run this again.")
        return

    print("Chats that wrote to the bot:")
    for chat_id, kind in chats.items():
        print("  chat id:", chat_id, " type:", kind)


if __name__ == "__main__":
    main()