"""
Regex Data Extraction Tool — extracts 8 data types from raw text.
Security: dangerous inputs are rejected; credit cards are masked before output.
"""

import re
import json
from pathlib import Path


# ─────────────────────────────────────────────────────────────
# SECURITY
# ─────────────────────────────────────────────────────────────

# Covers XSS, SQL injection, path traversal, and unsafe protocols.
_DANGEROUS_PATTERNS = [
    r"<script[\s>]",
    r"javascript\s*:",
    r"data\s*:",
    r"file\s*://",
    r"'\s*;.*(DROP|DELETE|INSERT|UPDATE|SELECT)",
    r"(DROP|DELETE)\s+TABLE",
    r"(?<!-)-{2}(?!-)",   # SQL comment (exactly --, not --- dividers)
    r"\.\./",             # Unix path traversal
    r"\.\.\\",            # Windows path traversal
]


def is_dangerous(text):
    """Returns True if text contains any known malicious pattern."""
    return any(re.search(p, text, re.IGNORECASE) for p in _DANGEROUS_PATTERNS)


def _get_context(text, start, end, radius=60):
    """Returns surrounding text around a match to detect injection context."""
    return text[max(0, start - radius): min(len(text), end + radius)]


# ─────────────────────────────────────────────────────────────
# EMAILS
# ─────────────────────────────────────────────────────────────

def extract_emails(text):
    """
    Extracts emails and sorts into 5 buckets: alu_official, alu_alumni,
    alu_si, other, rejected.
    Pattern: local-part @ domain . TLD (word boundaries prevent partials).
    """
    pattern = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
    result = {"alu_official": [], "alu_alumni": [], "alu_si": [], "other": [], "rejected": []}

    for m in pattern.finditer(text):
        addr = m.group()
        # Reject if the address or its surroundings contain dangerous patterns.
        if is_dangerous(addr) or is_dangerous(_get_context(text, m.start(), m.end())):
            result["rejected"].append(addr)
        else:
            # Most-specific domain checked first to avoid alumni matching alu_official.
            result[_alu_bucket(addr)].append(addr)

    return result


def _alu_bucket(email):
    """Returns the ALU category for an email based on its domain."""
    domain = email.split("@")[-1].lower()
    if domain == "alumni.alueducation.com":  return "alu_alumni"
    if domain == "si.alueducation.com":      return "alu_si"
    if domain == "alueducation.com":         return "alu_official"
    return "other"


# ─────────────────────────────────────────────────────────────
# CREDIT CARDS
# ─────────────────────────────────────────────────────────────

def _luhn_check(digits):
    """Validates a card number with the Luhn checksum algorithm."""
    total = 0
    for i, d in enumerate(reversed(digits)):
        n = int(d)
        if i % 2 == 1:
            n *= 2
            if n > 9: n -= 9
        total += n
    return total % 10 == 0


def _valid_card(digits):
    """
    Checks card prefix (Visa=4/16, Mastercard=51-55/16, Amex=34|37/15)
    and Luhn checksum. Rejects all-same-digit numbers (clearly fake).
    """
    if len(set(digits)) == 1:
        return False
    if len(digits) == 16 and (digits[0] == '4' or digits[:2] in ['51','52','53','54','55']):
        return _luhn_check(digits)
    if len(digits) == 15 and digits[:2] in ['34', '37']:
        return _luhn_check(digits)
    return False


def _mask_card(digits):
    """Masks all but the last 4 digits. Raw card numbers must never be stored."""
    last4 = digits[-4:]
    return ("**** ****** *" if len(digits) == 15 else "**** **** **** ") + last4


def extract_credit_cards(text):
    """
    Matches card numbers with optional space/dash separators (13-19 digits).
    Valid cards are masked immediately; invalid or dangerous ones are rejected.
    """
    pattern = re.compile(r"\b(?:\d[ -]?){13,19}\d\b")
    masked, rejected, warnings = [], [], []

    for m in pattern.finditer(text):
        raw = m.group()
        digits = re.sub(r"[^0-9]", "", raw)
        if is_dangerous(raw):
            warnings.append(f"Dangerous content near card at position {m.start()}")
            rejected.append("REDACTED")
        elif _valid_card(digits):
            masked.append(_mask_card(digits))
        else:
            rejected.append("INVALID/REDACTED")

    return {"count": len(masked), "masked": masked,
            "rejected_count": len(rejected), "security_warnings": warnings}


# ─────────────────────────────────────────────────────────────
# URLs
# ─────────────────────────────────────────────────────────────

def extract_urls(text):
    """
    Matches http, https, and ftp URLs only — dangerous protocols (javascript:,
    data:, file://) are excluded by the pattern itself before any safety check.
    """
    pattern = re.compile(r"\b(?:https?|ftp)://[^\s'\"<>]+", re.IGNORECASE)
    valid, rejected, warnings = [], [], []

    for m in pattern.finditer(text):
        url = m.group()
        if is_dangerous(url):
            warnings.append(f"Dangerous URL blocked: {url[:60]}")
            rejected.append("BLOCKED")
        else:
            valid.append(url)

    return {"valid": valid, "rejected_count": len(rejected), "security_warnings": warnings}


# ─────────────────────────────────────────────────────────────
# PHONE NUMBERS
# ─────────────────────────────────────────────────────────────

def extract_phones(text):
    """
    Three patterns cover international (+country code), US parentheses,
    and simple three-group formats. Substrings of longer matches are removed.
    """
    patterns = [
        re.compile(r"\+\d{1,3}[ -]?(?:\(\d{1,4}\)[ -]?)?\d{2,4}[ -]?\d{2,4}(?:[ -]?\d{2,4})?"),
        re.compile(r"\(\d{3,4}\)[ -]?\d{3,4}[ -]?\d{4}"),
        re.compile(r"\b\d{3}[ -]\d{3,4}[ -]\d{4}\b"),
    ]
    candidates = {m.strip() for p in patterns for m in p.findall(text)}
    phones = [p for p in candidates
              if (d := re.sub(r"\D", "", p)) and len(d) >= 7 and d.lstrip("0")]

    phones.sort(key=len, reverse=True)
    final = []
    for p in phones:
        if not any(p in longer for longer in final):
            final.append(p)
    return sorted(final)


# ─────────────────────────────────────────────────────────────
# TIME
# ─────────────────────────────────────────────────────────────

def extract_times(text):
    """
    12-hour: hours 1-12 + minutes 00-59 + AM/PM.
    24-hour: hours 00-23 + minutes 00-59 (times already in 12h list excluded).
    """
    p12 = re.compile(r"\b(?:1[0-2]|0?[1-9]):[0-5][0-9]\s?(?:AM|PM|am|pm)\b")
    p24 = re.compile(r"\b(?:[01]?\d|2[0-3]):[0-5][0-9]\b")

    times_12 = p12.findall(text)
    bare_12  = {t.split()[0] for t in times_12}  # strip AM/PM for dedup
    times_24 = [t for t in p24.findall(text) if t not in bare_12]

    return {"12hour": times_12, "24hour": times_24}


# ─────────────────────────────────────────────────────────────
# CURRENCY
# ─────────────────────────────────────────────────────────────

def extract_currency(text):
    """Matches $, €, £ amounts with optional thousands separators and decimals."""
    return re.compile(r"(?:\$|€|£)\s?\d{1,3}(?:,\d{3})*(?:\.\d{2})?").findall(text)


# ─────────────────────────────────────────────────────────────
# HASHTAGS
# ─────────────────────────────────────────────────────────────

def extract_hashtags(text):
    """Extracts #hashtags that contain at least one letter (rejects #123 style)."""
    return [t for t in re.compile(r"#[A-Za-z0-9_]+").findall(text)
            if re.search(r"[A-Za-z]", t) and len(t) <= 101]


# ─────────────────────────────────────────────────────────────
# HTML TAGS
# ─────────────────────────────────────────────────────────────

def extract_html_tags(text):
    """
    Extracts HTML tags and flags dangerous ones: <script>, event handlers
    (onclick=, onerror=, etc.), javascript: URIs, or any is_dangerous() match.
    """
    tag_re  = re.compile(r"</?[A-Za-z0-9-]+(?:\s+[^>]+)?>")
    evil_re = re.compile(r"\bon\w+\s*=|javascript\s*:", re.IGNORECASE)
    safe, flagged, warnings = [], [], []

    for tag in tag_re.findall(text):
        if "script" in tag.lower() or evil_re.search(tag) or is_dangerous(tag):
            warnings.append(f"Dangerous tag blocked: {tag[:80]}")
            flagged.append(tag)
        else:
            safe.append(tag)

    return {"safe": safe, "flagged": flagged, "security_warnings": warnings}


# ─────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────

def main():
    print("=== Regex Data Extraction Tool ===\n")

    input_path = Path(__file__).parent / ".." / "input" / "raw-text.txt"
    raw_text = input_path.read_text(encoding="utf-8")
    print(f"Input loaded: {len(raw_text)} characters\n")

    if is_dangerous(raw_text):
        print("WARNING: Suspicious patterns detected — dangerous matches will be rejected.\n")

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

    # Consolidate security warnings from all extractors.
    results["security_warnings"] = (
        results["credit_cards"]["security_warnings"] +
        results["urls"]["security_warnings"] +
        results["html_tags"]["security_warnings"]
    )

    output_path = Path(__file__).parent / ".." / "output" / "sample-output.json"
    output_path.write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Results saved to: {output_path.resolve()}\n")

    e = results["emails"]
    print("--- EXTRACTION SUMMARY ---")
    print(f"  Emails (ALU official) : {len(e['alu_official'])}")
    print(f"  Emails (ALU alumni)   : {len(e['alu_alumni'])}")
    print(f"  Emails (ALU SI)       : {len(e['alu_si'])}")
    print(f"  Emails (other)        : {len(e['other'])}")
    print(f"  Emails rejected       : {len(e['rejected'])}")
    print(f"  Credit cards valid    : {results['credit_cards']['count']}  (all masked)")
    print(f"  Credit cards rejected : {results['credit_cards']['rejected_count']}")
    print(f"  URLs valid            : {len(results['urls']['valid'])}")
    print(f"  URLs rejected         : {results['urls']['rejected_count']}")
    print(f"  Phone numbers         : {len(results['phones'])}")
    print(f"  Times (12-hour)       : {len(results['times']['12hour'])}")
    print(f"  Times (24-hour)       : {len(results['times']['24hour'])}")
    print(f"  Currency amounts      : {len(results['currency'])}")
    print(f"  Hashtags              : {len(results['hashtags'])}")
    print(f"  HTML tags (safe)      : {len(results['html_tags']['safe'])}")
    print(f"  HTML tags (flagged)   : {len(results['html_tags']['flagged'])}")
    print(f"  Security warnings     : {len(results['security_warnings'])}")


if __name__ == "__main__":
    main()
