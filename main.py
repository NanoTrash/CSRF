import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from http.cookies import SimpleCookie
import sys
import re
import json

STATIC_ANALYSIS = True  # <-- ключевой флаг

# Расширенные паттерны токенов CSRF
CSRF_TOKEN_PATTERNS = [
    "csrf", "xsrf", "token", "nonce", "authenticity", "anti",
    "_token", "csrf_token", "xsrf_token", "anticsrf",
    "csrfmiddlewaretoken", "__RequestVerificationToken",
    "state", "code_challenge", "jcsrf"
]

# Паттерны для state-changing действий
STATE_CHANGING_KEYWORDS = [
    "update", "edit", "change", "delete", "remove",
    "save", "submit", "create", "add", "purchase",
    "transfer", "withdraw", "deposit", "buy", "sell",
    "email", "mail", "profile", "user", "password",
    "account", "phone", "address", "settings", "config",
    "activate", "deactivate", "enable", "disable",
    "confirm", "cancel", "unsubscribe", "subscribe"
]

# Паттерны для login форм (исключения)
LOGIN_KEYWORDS = [
    "login", "signin", "auth", "password", "pass", "uname", "username",
    "sign_in", "authenticate", "log_in", "session"
]

# Паттерны для read-only действий (исключения)
READ_ONLY_KEYWORDS = [
    "search", "query", "lookup", "find", "filter", "view", "list",
    "browse", "read", "display", "show", "get", "fetch", "preview"
]

# Безопасные HTTP методы
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

# Заголовки, которые могут указывать на API
API_HEADERS = [
    "application/json", "application/xml", "text/xml",
    "application/x-amz-json-1.1", "application/graphql"
]


def looks_like_csrf_token(name: str) -> bool:
    """Проверяет, похоже ли имя поля на CSRF-токен."""
    return any(k in name.lower() for k in CSRF_TOKEN_PATTERNS)


def looks_state_changing(name: str) -> bool:
    """Проверяет, похоже ли имя поля на изменяющее состояние."""
    return any(k in name.lower() for k in STATE_CHANGING_KEYWORDS)


def looks_login_form(fields) -> bool:
    """Проверяет, является ли форма логина."""
    return any(
        k in f.lower()
        for f in fields
        for k in LOGIN_KEYWORDS
    )


def looks_read_only(fields) -> bool:
    """Проверяет, является ли форма read-only."""
    return all(
        any(k in f.lower() for k in READ_ONLY_KEYWORDS)
        for f in fields
    )


def parse_samesite(cookie_header: str) -> dict:
    """Парсит заголовки Set-Cookie для определения SameSite."""
    cookies = {}
    if not cookie_header:
        return cookies

    try:
        for part in cookie_header.split(","):
            c = SimpleCookie()
            c.load(part)
            for k, v in c.items():
                cookies[k] = v["samesite"].lower() if "samesite" in v else None
    except Exception:
        pass  # Игнорировать некорректные заголовки
    return cookies


def extract_hidden_inputs(form):
    """Извлекает скрытые input-элементы."""
    hidden_inputs = []
    for inp in form.find_all("input", type="hidden"):
        name = inp.get("name")
        value = inp.get("value")
        if name:
            hidden_inputs.append((name, value))
    return hidden_inputs


def check_js_csrf_tokens(soup, url):
    """Статический поиск CSRF-токенов в JavaScript."""
    tokens_found = []
    scripts = soup.find_all("script", src=False)  # Только inline-скрипты
    
    js_content = "\n".join([s.string or "" for s in scripts if s.string])
    
    # Ищем common JS patterns
    csrf_patterns = [
        r'["\']([^"\']*csrf[^"\']*)["\'][\s\n\r]*:[\s\n\r]*["\']?([^"\',\}>\s]*)',
        r'["\']?_?token["\']?\s*[=:]\s*["\']?([^"\'>\s]*)',
        r'\b(csrf|xsrf)[_\-]?(token|key|value)["\']?\s*[=:]\s*["\']?([^"\'>\s]*)',
        r'document\.getElementById\(["\']?([^"\']*)["\']?\)\.value'
    ]
    
    for pattern in csrf_patterns:
        matches = re.findall(pattern, js_content, re.IGNORECASE)
        for match in matches:
            if isinstance(match, tuple):
                tokens_found.extend([m for m in match if m.strip()])
            else:
                tokens_found.append(match)
                
    return list(set(tokens_found))


def analyze_form(idx, form, base_url, cookies_samesite, js_tokens):
    method = form.get("method", "GET").upper()
    action = urljoin(base_url, form.get("action", ""))
    parsed_action = urlparse(action)

    inputs = form.find_all(["input", "textarea", "select"])
    fields = [i.get("name") for i in inputs if i.get("name")]
    field_types = [i.get("type", "text") for i in inputs if i.get("type")]

    # Проверяем наличие CSRF-токена
    has_csrf_token = any(looks_like_csrf_token(f) for f in fields)
    has_js_csrf = any(looks_like_csrf_token(t) for t in js_tokens)

    # Проверяем hidden поля
    hidden_fields = extract_hidden_inputs(form)
    has_hidden_csrf = any(looks_like_csrf_token(name) for name, _ in hidden_fields)

    # Проверяем state-changing
    state_changing = (
        method not in SAFE_METHODS
        or any(looks_state_changing(f) for f in fields)
        or any(keyword in parsed_action.path.lower() for keyword in STATE_CHANGING_KEYWORDS)
    )

    verdict = {
        "index": idx,
        "action": action,
        "method": method,
        "fields": fields,
        "field_types": field_types,
        "confidence": 0,
        "signals": [],
        "penalties": [],
        "csrf_candidate": False,
        "js_tokens": js_tokens[:3],  # первые 3 найденных токена
        "hidden_fields": [f"{k}={v}" for k, v in hidden_fields]
    }

    # ===== SIGNALS =====
    if method in {"POST", "PUT", "PATCH", "DELETE"}:
        verdict["confidence"] += 25
        verdict["signals"].append("Unsafe HTTP method")

    if state_changing:
        verdict["confidence"] += 30
        verdict["signals"].append("State-changing semantics")

    if not has_csrf_token:
        verdict["confidence"] += 25
        verdict["signals"].append("No visible CSRF token in form")
    else:
        verdict["signals"].append("Found CSRF token in form")

    if not has_js_csrf:
        verdict["confidence"] += 10
        verdict["signals"].append("No CSRF token found in JS")
    else:
        verdict["signals"].append("Found CSRF token in JS")

    if not has_hidden_csrf:
        verdict["confidence"] += 10
        verdict["signals"].append("No hidden CSRF token")
    else:
        verdict["signals"].append("Found hidden CSRF token")

    if cookies_samesite:
        verdict["confidence"] += 5
        verdict["signals"].append("Session cookies present")
        
        # Проверяем, есть ли строгие SameSite
        if not any(v and 'strict' in v.lower() for v in cookies_samesite.values()):
            verdict["confidence"] += 10
            verdict["signals"].append("No SameSite=Strict cookies")

    # Проверяем на API endpoints
    content_type = form.get("enctype", "")
    if any(api in content_type.lower() for api in ["json", "xml"]):
        verdict["confidence"] += 15
        verdict["signals"].append("API-like form encoding")

    # ===== PENALTIES (STATIC MODE) =====
    if looks_login_form(fields):
        verdict["confidence"] -= 40
        verdict["penalties"].append("Authentication form (Login CSRF)")

    if looks_read_only(fields):
        verdict["confidence"] -= 50
        verdict["penalties"].append("Read-only / search-like form")

    # Проверяем, содержит ли форма только безопасные поля
    safe_fields_only = all(
        f.lower() in ["q", "query", "search", "page", "limit", "offset"]
        or any(k in f.lower() for k in READ_ONLY_KEYWORDS)
        for f in fields
    )
    if safe_fields_only and method == "GET":
        verdict["confidence"] -= 30
        verdict["penalties"].append("Safe query-only form")

    # Clamp score
    verdict["confidence"] = max(0, min(100, verdict["confidence"]))

    # STATIC verdict
    if verdict["confidence"] >= 60:
        verdict["csrf_candidate"] = True

    return verdict


def dynamic_analysis(url, session, form_element, form_idx):
    """Дополнительный анализ формы с отправкой пробного запроса (опционально)."""
    try:
        # Это будет работать только если STATIC_ANALYSIS = False
        if STATIC_ANALYSIS:
            return {}
            
        method = form_element.get("method", "GET").upper()
        action = urljoin(url, form_element.get("action", ""))
        
        inputs = form_element.find_all(["input", "textarea", "select"])
        form_data = {}
        
        for inp in inputs:
            name = inp.get("name")
            value = inp.get("value", "")
            inp_type = inp.get("type", "text").lower()
            
            if name and inp_type not in ["submit", "button", "reset"]:
                # Подставляем фиктивное значение для не-CSRF полей
                if not looks_like_csrf_token(name):
                    if inp_type == "email":
                        form_data[name] = "test@example.com"
                    elif inp_type == "password":
                        form_data[name] = "password123"
                    elif inp_type == "number":
                        form_data[name] = "1"
                    else:
                        form_data[name] = "test_value"
                else:
                    # Оставляем CSRF-токены пустыми для тестирования
                    form_data[name] = ""
        
        # Отправляем пробный запрос
        response = session.post(action, data=form_data, timeout=5, allow_redirects=True)
        
        # Анализируем ответ на наличие признаков CSRF защиты
        response_signals = []
        if response.status_code in [400, 401, 403, 419]:
            response_signals.append("Server rejected request (good sign)")
        elif response.status_code == 200:
            # Проверяем, вернулся ли тот же запрос или есть ошибка токена
            if any(token_word in response.text.lower() for token_word in ["csrf", "token", "invalid"]):
                response_signals.append("Response mentions token error")
        
        return {
            "dynamic_status": response.status_code,
            "response_signals": response_signals
        }
        
    except Exception as e:
        return {"dynamic_error": str(e)}


def scan(url):
    session = requests.Session()
    # Устанавливаем User-Agent чтобы не блокировались
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    })
    
    try:
        r = session.get(url, timeout=10)
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Could not fetch URL: {e}")
        return

    soup = BeautifulSoup(r.text, "lxml")
    forms = soup.find_all("form")

    cookies_samesite = parse_samesite(r.headers.get("Set-Cookie"))
    
    # Поиск токенов в JS
    js_tokens = check_js_csrf_tokens(soup, url)

    print(f"\n[+] Target: {url}")
    print(f"[+] Mode: STATIC (no authentication)")
    print(f"[+] Forms found: {len(forms)}")
    print(f"[+] JS tokens found: {len(js_tokens)}")
    if js_tokens:
        print(f"    Tokens: {js_tokens[:5]}")
    print()

    for idx, form in enumerate(forms, 1):
        result = analyze_form(idx, form, url, cookies_samesite, js_tokens)

        print(f"[FORM #{idx}]")
        print(f"  Action     : {result['action']}")
        print(f"  Method     : {result['method']}")
        print(f"  Fields     : {result['fields']}")
        print(f"  Field Types: {result['field_types']}")
        print(f"  Hidden Flds: {result['hidden_fields']}")
        print(f"  JS Tokens  : {result['js_tokens']}")
        print(f"  Score      : {result['confidence']}/100")

        if result["csrf_candidate"]:
            print("  >>> CSRF CANDIDATE (STATIC ANALYSIS) <<<")

        if result["signals"]:
            print("  Signals:")
            for s in result["signals"]:
                print(f"   + {s}")

        if result["penalties"]:
            print("  Penalties:")
            for p in result["penalties"]:
                print(f"   - {p}")

        print("-" * 50)


def main():
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <url>")
        sys.exit(1)

    target_url = sys.argv[1]
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'https://' + target_url

    scan(target_url)


if __name__ == "__main__":
    main()
