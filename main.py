import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from http.cookies import SimpleCookie
import sys


STATIC_ANALYSIS = True  # <-- ключевой флаг


CSRF_TOKEN_PATTERNS = [
    "csrf", "xsrf", "token", "nonce", "authenticity", "anti"
]

STATE_CHANGING_KEYWORDS = [
    "update", "edit", "change", "delete", "remove",
    "save", "submit", "create", "add",
    "email", "mail", "profile", "user",
    "account", "phone", "address"
]

LOGIN_KEYWORDS = [
    "login", "signin", "auth", "password", "pass", "uname", "username"
]

READ_ONLY_KEYWORDS = [
    "search", "query", "lookup", "find", "filter", "view", "list"
]

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def looks_like_csrf_token(name: str) -> bool:
    return any(k in name.lower() for k in CSRF_TOKEN_PATTERNS)


def looks_state_changing(name: str) -> bool:
    return any(k in name.lower() for k in STATE_CHANGING_KEYWORDS)


def looks_login_form(fields) -> bool:
    return any(
        k in f.lower()
        for f in fields
        for k in LOGIN_KEYWORDS
    )


def looks_read_only(fields) -> bool:
    return all(
        any(k in f.lower() for k in READ_ONLY_KEYWORDS)
        for f in fields
    )


def parse_samesite(cookie_header: str) -> dict:
    cookies = {}
    if not cookie_header:
        return cookies

    for part in cookie_header.split(","):
        c = SimpleCookie()
        c.load(part)
        for k, v in c.items():
            cookies[k] = v["samesite"].lower() if "samesite" in v else None
    return cookies


def analyze_form(idx, form, base_url, cookies_samesite):
    method = form.get("method", "GET").upper()
    action = urljoin(base_url, form.get("action", ""))

    inputs = form.find_all(["input", "textarea", "select"])
    fields = [i.get("name") for i in inputs if i.get("name")]

    has_csrf_token = any(looks_like_csrf_token(f) for f in fields)
    state_changing = (
        method not in SAFE_METHODS
        or any(looks_state_changing(f) for f in fields)
    )

    verdict = {
        "index": idx,
        "action": action,
        "method": method,
        "fields": fields,
        "confidence": 0,
        "signals": [],
        "penalties": [],
        "csrf_candidate": False
    }

    # ===== SIGNALS =====
    if method in {"POST", "PUT", "PATCH"}:
        verdict["confidence"] += 25
        verdict["signals"].append("Unsafe HTTP method")

    if state_changing:
        verdict["confidence"] += 30
        verdict["signals"].append("State-changing semantics")

    if not has_csrf_token:
        verdict["confidence"] += 25
        verdict["signals"].append("No CSRF token")

    if cookies_samesite:
        verdict["confidence"] += 10
        verdict["signals"].append("Cookies present")

    if not any(v == "strict" for v in cookies_samesite.values()):
        verdict["confidence"] += 10
        verdict["signals"].append("No SameSite=Strict")

    # ===== PENALTIES (STATIC MODE) =====
    if looks_login_form(fields):
        verdict["confidence"] -= 40
        verdict["penalties"].append("Authentication form (Login CSRF)")

    if looks_read_only(fields):
        verdict["confidence"] -= 50
        verdict["penalties"].append("Read-only / search-like form")

    # Clamp score
    verdict["confidence"] = max(0, min(100, verdict["confidence"]))

    # STATIC verdict
    if verdict["confidence"] >= 60:
        verdict["csrf_candidate"] = True

    return verdict


def scan(url):
    session = requests.Session()
    r = session.get(url, timeout=10)

    soup = BeautifulSoup(r.text, "lxml")
    forms = soup.find_all("form")

    cookies_samesite = parse_samesite(r.headers.get("Set-Cookie"))

    print(f"\n[+] Target: {url}")
    print(f"[+] Mode: STATIC (no authentication)")
    print(f"[+] Forms found: {len(forms)}\n")

    for idx, form in enumerate(forms, 1):
        result = analyze_form(idx, form, url, cookies_samesite)

        print(f"[FORM #{idx}]")
        print(f"  Action     : {result['action']}")
        print(f"  Method     : {result['method']}")
        print(f"  Fields     : {result['fields']}")
        print(f"  Score      : {result['confidence']}/100")

        if result["csrf_candidate"]:
            print("  >>> CSRF CANDIDATE (STATIC) <<<")

        if result["signals"]:
            print("  Signals:")
            for s in result["signals"]:
                print(f"   + {s}")

        if result["penalties"]:
            print("  Penalties:")
            for p in result["penalties"]:
                print(f"   - {p}")

        print()


def main():
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <url>")
        sys.exit(1)

    scan(sys.argv[1])


if __name__ == "__main__":
    main()
