## Step 3: Setting Up `main.py`

Open `src/main.py` in VS Code and paste this skeleton. This is just the structure — no regex yet, we fill each function one by one after this.

```python
import re
import json
from pathlib import Path


# ============================================================
# Utilities
# ============================================================
def read_input(filepath):
    """Reads the raw text file and returns its content as a string."""
    p = Path(filepath)
    return p.read_text(encoding='utf-8')


def is_dangerous(text):
    """Basic heuristics to detect obviously malicious or file/protocol-based payloads.

    This is intentionally conservative: if a substring looks like an injection or
    unsafe resource (javascript:, data:, file://, DROP TABLE, <script>), treat as
    dangerous and do not accept as valid extracted data.
    """
    lowered = text.lower()
    checks = ["javascript:", "data:", "file:/", "drop table", "<script", "../", "..\\"]
    return any(c in lowered for c in checks)


# ============================================================
# Extraction helpers
# ============================================================

def extract_emails(text):
    """Extract email addresses and categorize ALU-specific domains.

    Returns a dict with categories and a rejected list for unsafe/malformed items.
    """
    # General RFC-like simple pattern (practical, not fully RFC5322)
    email_re = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
    found = email_re.findall(text)
    results = {"alu_official": [], "alu_alumni": [], "alu_si": [], "other": [], "rejected": []}

    for e in found:
        if is_dangerous(e):
            results['rejected'].append({"value": e, "reason": "unsafe pattern"})
            continue
        domain = e.split('@')[-1].lower()
        if domain == 'alueducation.com':
            results['alu_official'].append(e)
        elif domain == 'alumni.alueducation.com':
            results['alu_alumni'].append(e)
        elif domain == 'si.alueducation.com':
            results['alu_si'].append(e)
        else:
            results['other'].append(e)

    return results


def extract_credit_cards(text):
    """Extract credit card-looking sequences, validate with Luhn, and mask.

    Returns dict with masked cards, count, and rejected suspicious entries.
    """
    # Match groups of 13-19 digits with optional spaces or dashes
    card_re = re.compile(r"\b(?:\d[ -]?){13,19}\b")
    matches = card_re.findall(text)
    cards = []
    rejected = []

    for raw in matches:
        digits = re.sub(r"[^0-9]", "", raw)
        if is_dangerous(raw):
            rejected.append({"value": raw, "reason": "unsafe pattern"})
            continue
        if not is_valid_card(digits):
            rejected.append({"value": raw, "reason": "invalid-luhn-or-length"})
            continue
        cards.append(mask_card(digits))

    return {"masked": cards, "count": len(cards), "rejected": rejected}


def mask_card(digits):
    """Return masked card string grouping in 4s, showing only last 4 digits."""
    last4 = digits[-4:]
    groups = []
    # Build groups of 4 from the right
    for i in range(len(digits) - 4, 0, -4):
        groups.append('****')
    groups = list(reversed(groups))
    groups.append(last4)
    return ' '.join(groups)


def is_valid_card(digits):
    """Luhn check and reasonable length guard (13-19 digits)."""
    if not (13 <= len(digits) <= 19):
        return False
    # avoid trivial or repeated-digit fakes
    if len(set(digits)) == 1:
        return False

    # Luhn algorithm
    total = 0
    reverse_digits = digits[::-1]
    for i, ch in enumerate(reverse_digits):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def extract_urls(text):
    """Extract http(s) URLs, filter out unsafe protocols and suspicious patterns."""
    url_re = re.compile(r"\bhttps?://[^\s'\"<>]+", re.IGNORECASE)
    found = url_re.findall(text)
    valid = []
    rejected = []
    for u in found:
        if is_dangerous(u):
            rejected.append({"value": u, "reason": "unsafe-protocol-or-payload"})
            continue
        valid.append(u)
    return {"valid": valid, "rejected": rejected}


def extract_phones(text):
    """Extract phone numbers in common international and local formats."""
    phone_re = re.compile(r"\b(?:\+\d{1,3}[ -]?)?(?:\(\d{1,4}\)|\d{1,4})[ -]?\d{2,4}[ -]?\d{2,4}[ -]?\d{0,4}\b")
    # Fallback simpler patterns when above doesn't catch all
    phone_re_simple = re.compile(r"\b\+?\d{1,3}[ -]?\d{3,4}[ -]?\d{3,4}\b")
    found = phone_re.findall(text)
    found_simple = phone_re_simple.findall(text)
    candidates = set(found + found_simple)
    phones = []
    for p in candidates:
        normalized = re.sub(r"[^0-9+]", "", p)
        # Reject all-zero or very short sequences
        if normalized.strip('+').lstrip('0') == '':
            continue
        if len(re.sub(r"[^0-9]", "", normalized)) < 7:
            continue
        phones.append(p.strip())
    return phones


def extract_times(text):
    """Find 12-hour and 24-hour times.

    Returns dict with two lists: 12hour and 24hour.
    """
    t12 = re.findall(r"\b(?:1[0-2]|0?[1-9]):[0-5][0-9]\s?(?:AM|PM|am|pm)\b", text)
    t24 = re.findall(r"\b(?:[01]?\d|2[0-3]):[0-5][0-9]\b", text)
    # Remove overlaps (12-hour matches may also match 24h pattern), keep separate
    t24_only = [t for t in t24 if t not in t12]
    return {"12hour": t12, "24hour": t24_only}


def extract_currency(text):
    """Extract currency amounts with common symbols."""
    cur = re.findall(r"\b(?:\$|€|£)\s?\d{1,3}(?:,\d{3})*(?:\.\d{2})?\b", text)
    return cur


def extract_hashtags(text):
    return re.findall(r"#[A-Za-z0-9_]+", text)


def extract_html_tags(text):
    return re.findall(r"</?[A-Za-z0-9\-]+(?:\s+[^>]+)?>", text)


# ============================================================
# MAIN
# ============================================================

def main():
    print("=== Regex Data Extraction Tool ===\n")

    # Read input (file resides in ../input relative to src)
    raw_text = read_input(Path(__file__).parent.joinpath('..', 'input', 'raw-text.text'))
    print(f"Input loaded: {len(raw_text)} characters\n")

    # Quick global safety check (detect obviously hostile full document)
    if is_dangerous(raw_text) and '--- FLAGGED SUSPICIOUS SUBMISSIONS ---' not in raw_text:
        print("Warning: input contains suspicious content; processing with extra caution.")

    results = {
        "emails":       extract_emails(raw_text),
        "credit_cards": extract_credit_cards(raw_text),
        "urls":         extract_urls(raw_text),
        "phones":       extract_phones(raw_text),
        "times":        extract_times(raw_text),
        "currency":     extract_currency(raw_text),
        "hashtags":     extract_hashtags(raw_text),
        "html_tags":    extract_html_tags(raw_text),
    }

    out_path = Path(__file__).parent.joinpath('..', 'output', 'sample-output.json')
    out_path.write_text(json.dumps(results, indent=2), encoding='utf-8')
    print(f"Results saved to {out_path}\n")

    # Print summary
    email_count = sum(len(v) for k, v in results['emails'].items() if k != 'rejected')
    print("--- SUMMARY ---")
    print(f"Emails found:       {email_count}")
    print(f"Credit cards found: {results['credit_cards']['count']} (masked)")
    print(f"URLs found:         {len(results['urls']['valid'])}")
    print(f"Phones found:       {len(results['phones'])}")
    print(f"Times found:        {len(results['times']['12hour']) + len(results['times']['24hour'])}")
    print(f"Currency found:     {len(results['currency'])}")
    print(f"Hashtags found:     {len(results['hashtags'])}")
    print(f"HTML tags found:    {len(results['html_tags'])}")


if __name__ == "__main__":
    main()