import json
import os
import urllib.error
import urllib.request

import msal
from dotenv import load_dotenv

from paths import path_in_app

AUTHORITY = "https://login.microsoftonline.com/consumers"
SCOPES = ["Mail.Read", "MailboxSettings.Read"]
CACHE_FILE = path_in_app("token_cache.json")
GRAPH_URL = "https://graph.microsoft.com/v1.0"


def load_cache():
    cache = msal.SerializableTokenCache()
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE) as f:
            cache.deserialize(f.read())
    return cache


def save_cache(cache):
    if cache.has_state_changed:
        fd = os.open(CACHE_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(cache.serialize())
        os.chmod(CACHE_FILE, 0o600)


def get_token(interactive=True):
    load_dotenv(path_in_app(".env"))
    client_id = os.environ.get("MS_CLIENT_ID", "")
    if not client_id:
        raise RuntimeError("Set MS_CLIENT_ID in the .env file.")

    cache = load_cache()
    app = msal.PublicClientApplication(client_id, authority=AUTHORITY, token_cache=cache)

    result = None
    accounts = app.get_accounts()
    if accounts:
        result = app.acquire_token_silent(SCOPES, account=accounts[0])

    if not result:
        if not interactive:
            raise RuntimeError("The saved sign in is missing or expired.")
        flow = app.initiate_device_flow(scopes=SCOPES)
        if "user_code" not in flow:
            raise RuntimeError("Could not start the sign in. Check MS_CLIENT_ID and the app settings.")
        print(flow["message"])
        result = app.acquire_token_by_device_flow(flow)

    save_cache(cache)

    if "access_token" not in result:
        reason = result.get("error_description") or result.get("error") or "unknown error"
        raise RuntimeError("Sign in failed: " + str(reason))

    return result["access_token"]


def fetch(path, token, accept):
    request = urllib.request.Request(
        GRAPH_URL + path,
        headers={"Authorization": "Bearer " + token, "Accept": accept},
    )

    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.read()
    except urllib.error.HTTPError as error:
        if error.code == 401:
            raise RuntimeError("Microsoft rejected the token. Delete token_cache.json and sign in again.")
        if error.code == 403:
            raise RuntimeError("Permission missing. Check the API permissions of the app registration.")
        raise RuntimeError("Microsoft Graph refused the request with code " + str(error.code) + ".")
    except (OSError, ValueError):
        raise RuntimeError("Microsoft Graph could not be reached.")


def graph_get(path, token):
    body = fetch(path, token, "application/json")
    try:
        return json.loads(body.decode("utf-8"))
    except ValueError:
        raise RuntimeError("Microsoft Graph sent an answer that could not be read.")


def graph_get_raw(path, token):
    return fetch(path, token, "*/*")