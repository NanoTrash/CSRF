# CSRF Static Checker

Static CSRF risk checker for HTML forms. Performs heuristic analysis without authentication or active exploitation. The tool does not claim confirmed vulnerabilities and is intended for risk surface discovery and pre-triage.

The checker parses forms from a given URL, evaluates HTTP methods, field semantics, CSRF token presence, and cookie attributes, then assigns a deterministic risk score from 0 to 100. Forms with score ≥ 60 are marked as CSRF candidates in static mode. False positives are expected by design.

The tool does not handle sessions, does not execute JavaScript, does not validate server-side logic, and does not bypass protections such as Origin or Referer checks.

## Usage (Poetry)

```bash
poetry run python main.py http://testphp.vulnweb.com/userinfo.php
```

## Output

```bash
[+] Target: http://testphp.vulnweb.com/userinfo.php
[+] Mode: STATIC (no authentication)
[+] Forms found: 2

[FORM #1]
  Action     : http://testphp.vulnweb.com/userinfo.php
  Method     : POST
  Fields     : ['uname', 'pass']
  Score      : 50/100

[FORM #2]
  Action     : http://testphp.vulnweb.com/search.php
  Method     : POST
  Fields     : ['searchFor', 'goButton']
  Score      : 90/100
  CSRF CANDIDATE (STATIC)
```
