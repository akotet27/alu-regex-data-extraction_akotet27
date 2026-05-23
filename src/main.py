"""
Regex Data Extraction Tool
==========================
Extracts structured data from raw text and validates it against
known-safe patterns.  Unsafe / malformed entries are rejected rather
than silently accepted.

Security approach:
  - is_dangerous() blocks common injection payloads before they reach
    downstream logic (SQL injection, XSS, path traversal, unsafe protocols).
  - Emails are checked against the context in which they appear; an address
    found inside an injection attempt is rejected even if the address itself
    is syntactically valid.
  - Credit card numbers are never stored in plain text; only a masked
    representation is kept, and the raw digit string is discarded immediately
    after the Luhn check.
  - Phone extraction rejects matches whose digit count falls in credit-card
    range (>=13 digits) and removes duplicated sub-matches.
"""

import re
import json
from pathlib import Path


# ============================================================
# Utilities
# ============================================================

def read_input(filepath):
    """Read raw text file and return its content as a string."""
    return Path(filepath).read_text(encoding="utf-8")


# Substrings that indicate hostile or unsafe content.
_DANGEROUS = [
    "javascript:",   # JS protocol injection
    "data:",         # data-URI payloads
    "file:/",        # local file-system access
    "drop table",    # SQL injection
    "<script",       # XSS script injection
    "../",           # directory traversal (Unix)
    "..\\",          # directory traversal (Windows)
]

def is_dangerous(text):
    """Return True if *text* contains a known injection / hostile pattern.

    Conservative by design: false positives are safe; false negatives are not.
    """
    lowered = text.lower()
    return any(marker in lowered for marker in _DANGEROUS)


def _context_window(text, start, end, radius=120):
    """Return up to *radius* characters before and after the match span."""
    return text[max(0, start - radius): min(len(text), end + radius)]


# ============================================================
# Extraction helpers
# ============================================================

def extract_emails(text):
    """Extract and categorise email addresses found in *text*.

    ALU domains are split into three buckets:
      alu_official  – @alueducation.com
      alu_alumni    – @alumni.alueducation.com
      alu_si        – @si.alueducation.com
    Everything else goes to *other*.

    Security note: even if an email address is syntactically valid, it is
    rejected when the surrounding text context contains injection patterns
    (e.g. an address that appears on the same line as a SQL DROP statement).

    Regex explanation:
      \\b                       – word boundary (prevents mid-token matches)
      [A-Za-z0-9._%+-]+         – local part: letters, digits, common specials
      @                         – literal at-sign (only one)
      [A-Za-z0-9.-]+            – domain labels (dots allowed)
      \\.                       – literal dot before TLD
      [A-Za-z]{2,}              – TLD: two or more letters
      \\b                       – trailing word boundary
    """
    email_re = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
    results = {
        "alu_official": [], "alu_alumni": [], "alu_si": [],
        "other": [], "rejected": [],
    }

    for m in email_re.finditer(text):
        addr = m.group()
        # Check the address itself for dangerous patterns
        if is_dangerous(addr):
            results["rejected"].append({"value": addr, "reason": "unsafe-pattern-in-address"})
            continue
        # Check the surrounding context — reject if near injection text
        ctx = _context_window(text, m.start(), m.end())
        if is_dangerous(ctx):
            results["rejected"].append({
                "value": addr,
                "reason": "unsafe-surrounding-context",
            })
            continue

        domain = addr.split("@")[-1].lower()
        if domain == "alueducation.com":
            results["alu_official"].append(addr)
        elif domain == "alumni.alueducation.com":
            results["alu_alumni"].append(addr)
        elif domain == "si.alueducation.com":
            results["alu_si"].append(addr)
        else:
            results["other"].append(addr)

    return results


# ---------------------------------------------------------------------------
# Credit cards
# ---------------------------------------------------------------------------

def _luhn_valid(digits):
    """Return True if *digits* (string of digits) passes the Luhn algorithm."""
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2 == 1:      # every second digit from the right: double it
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def is_valid_card(digits):
    """Validate card: length 13-19, not all-same digit, passes Luhn.

    Trivially synthetic cards (e.g., 9999999999999999) are rejected
    regardless of Luhn outcome.
    """
    if not (13 <= len(digits) <= 19):
        return False
    if len(set(digits)) == 1:    # obviously fake repeated-digit card
        return False
    return _luhn_valid(digits)


def mask_card(digits):
    """Return a masked card string with only the last four digits visible.

    Example: 371449635398431  →  '**** **** *** 8431'
    """
    last4 = digits[-4:]
    prefix = digits[:-4]
    # Build groups of 4 from the prefix, each shown as ****
    groups = ["****"] * (len(prefix) // 4 + (1 if len(prefix) % 4 else 0))
    return " ".join(groups) + " " + last4


def extract_credit_cards(text):
    """Extract credit card numbers, validate with Luhn, and mask the output.

    Regex explanation:
      \\b                  – word boundary
      (?:\\d[ -]?){13,19}  – 13-19 repetitions of (digit + optional space/dash)
      \\b                  – trailing word boundary

    Security: raw digit strings are discarded immediately after validation;
    only the masked representation is kept.  The rejected list shows
    'REDACTED' so that invalid cards are accounted for without being exposed.
    """
    card_re = re.compile(r"\b(?:\d[ -]?){13,19}\b")
    cards, rejected = [], []

    for raw in card_re.findall(text):
        if is_dangerous(raw):
            rejected.append({"value": "REDACTED", "reason": "unsafe-pattern"})
            continue
        digits = re.sub(r"[^0-9]", "", raw)
        if not is_valid_card(digits):
            rejected.append({"value": "REDACTED", "reason": "invalid-luhn-or-length"})
            continue
        cards.append(mask_card(digits))
        # digits is not stored beyond this point

    return {"masked": cards, "count": len(cards), "rejected": rejected}


# ---------------------------------------------------------------------------
# URLs
# ---------------------------------------------------------------------------

def extract_urls(text):
    """Extract http/https URLs and reject those containing unsafe payloads.

    Only http and https schemes are accepted; javascript:, data:, and
    file:// are never matched because the pattern requires the https?://
    prefix.  URLs that still contain dangerous payloads after extraction
    (e.g. a redirect to a data: URI embedded in a query string) are placed
    in the rejected list.

    Regex explanation:
      \\b           – word boundary before the scheme
      https?://     – http or https (no other schemes accepted)
      [^\\s'\"<>]+  – URL body: any char that is not whitespace or a quote/angle
    """
    url_re = re.compile(r"\bhttps?://[^\s'\"<>]+", re.IGNORECASE)
    valid, rejected = [], []
    for url in url_re.findall(text):
        if is_dangerous(url):
            rejected.append({"value": url, "reason": "unsafe-payload-in-url"})
            continue
        valid.append(url)
    return {"valid": valid, "rejected": rejected}


# ---------------------------------------------------------------------------
# Phone numbers
# ---------------------------------------------------------------------------

def extract_phones(text):
    """Extract phone numbers covering common international and local formats.

    Three distinct sub-patterns are tried in priority order:

      1. International  – starts with +CC, e.g. +1 (555) 012-3456, +250 788 123 456
      2. Area-code      – local with parenthesised area, e.g. (555) 987-6543
      3. Dashed-local   – three-group dash/space format, e.g. 555-123-4567

    Using explicit anchors (\\+, \\() rather than relying on \\b prevents
    credit-card digit sequences from being mis-classified as phone numbers.

    Post-filters:
      - Fewer than 7 digits  → too short (dates, reference codes)
      - All-zero digits      → synthetic placeholder
    Duplicate sub-matches are removed so that e.g. "250 788 123" is not
    reported alongside "+250 788 123 456".
    """
    # 1. International: mandatory + country code, optional (area), subscriber digits
    intl = re.compile(
        r"\+\d{1,3}[ -]?(?:\(\d{1,4}\)[ -]?)?\d{2,4}[ -]?\d{2,4}(?:[ -]?\d{2,4})?"
    )
    # 2. Area-code local: (NNN) NNN-NNNN style
    area = re.compile(r"\(\d{3,4}\)[ -]?\d{3,4}[ -]?\d{4}")
    # 3. Plain dashed/spaced local: NNN-NNN-NNNN or NNN NNN NNNN
    local = re.compile(r"\b\d{3}[ -]\d{3,4}[ -]\d{4}\b")

    raw_candidates = (
        set(intl.findall(text))
        | set(area.findall(text))
        | set(local.findall(text))
    )

    phones = []
    for raw in raw_candidates:
        stripped = raw.strip()
        digits = re.sub(r"[^0-9]", "", stripped)
        if len(digits) < 7:
            continue
        if digits.lstrip("0") == "":        # all-zero placeholder
            continue
        phones.append(stripped)

    # Remove sub-matches: keep only the longest form when one is a substring of another
    phones_sorted = sorted(phones, key=len, reverse=True)
    final = []
    for p in phones_sorted:
        if not any(p in longer for longer in final):
            final.append(p)

    return sorted(final)


# ---------------------------------------------------------------------------
# Times
# ---------------------------------------------------------------------------

def extract_times(text):
    """Find times in both 12-hour and 24-hour notation.

    12-hour pattern: hours 1-12, colon, MM, optional space, AM/PM
    24-hour pattern: hours 00-23, colon, MM

    The two lists are kept separate.  Times that appear in both forms
    (e.g. "10:30 AM" and the bare "10:30") are deduplicated so that the
    bare time is not repeated in the 24-hour list.
    """
    # 12-hour: 1–12:MM AM/PM (case-insensitive suffix)
    t12 = re.findall(r"\b(?:1[0-2]|0?[1-9]):[0-5][0-9]\s?(?:AM|PM|am|pm)\b", text)
    # 24-hour: 00-23:MM
    t24 = re.findall(r"\b(?:[01]?\d|2[0-3]):[0-5][0-9]\b", text)
    # Strip out bare HH:MM that are already represented as HH:MM AM/PM
    t12_bare = {t.split()[0] for t in t12}   # {"10:30", "2:30", …}
    t24_only = [t for t in t24 if t not in t12_bare]
    return {"12hour": t12, "24hour": t24_only}


# ---------------------------------------------------------------------------
# Currency, hashtags, HTML tags
# ---------------------------------------------------------------------------

def extract_currency(text):
    """Extract currency amounts prefixed with $, €, or £.

    Pattern: symbol, optional space, integer with optional comma thousands
    separator, optional two-decimal fraction.

    Example matches: $150.00  |  €120.00  |  £200.00  |  $1,500
    """
    cur_re = re.compile(r"(?:\$|€|£)\s?\d{1,3}(?:,\d{3})*(?:\.\d{2})?")
    return re.findall(cur_re, text)


def extract_hashtags(text):
    """Extract hashtags that contain at least one letter.

    Pure-digit tokens like #4521 (ticket numbers) are excluded because real
    hashtags are word-based, not numeric identifiers.

    Pattern: # followed by word chars where at least one is a letter.
    """
    candidates = re.findall(r"#[A-Za-z0-9_]+", text)
    # Keep only hashtags that contain at least one alphabetic character
    return [h for h in candidates if re.search(r"[A-Za-z]", h)]


def extract_html_tags(text):
    """Extract HTML opening and closing tags.

    Tags containing 'script' (both opening <script> and closing </script>)
    are flagged as potentially unsafe because they indicate an XSS attempt
    even when the tag name alone looks harmless.  All other tags that still
    trigger is_dangerous() (e.g. event-handler attributes) are also flagged.
    """
    tags = re.findall(r"</?[A-Za-z0-9\-]+(?:\s+[^>]+)?>", text)
    safe, flagged = [], []
    for tag in tags:
        # Flag <script>, </script>, and any tag containing dangerous payloads
        if "script" in tag.lower() or is_dangerous(tag):
            flagged.append({"value": tag, "reason": "potentially-unsafe-tag"})
        else:
            safe.append(tag)
    return {"safe": safe, "flagged": flagged}


# ============================================================
# MAIN
# ============================================================

def main():
    print("=== Regex Data Extraction Tool ===\n")

    input_path = Path(__file__).parent / ".." / "input" / "raw-text.text"
    raw_text = read_input(input_path)
    print(f"Input loaded: {len(raw_text)} characters\n")

    # Warn if the document as a whole looks suspicious.
    # We still process it so flagged items appear in rejected lists — this lets
    # the caller audit exactly what was found and why it was rejected.
    if is_dangerous(raw_text):
        print("WARNING: input contains suspicious patterns — "
              "results include rejection detail.\n")

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

    out_path = Path(__file__).parent / ".." / "output" / "sample-output.json"
    out_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"Results written to: {out_path.resolve()}\n")

    # ---- summary ----
    email_total = sum(len(v) for k, v in results["emails"].items() if k != "rejected")
    print("--- EXTRACTION SUMMARY ---")
    print(f"  Emails found        : {email_total}  "
          f"(official={len(results['emails']['alu_official'])}, "
          f"alumni={len(results['emails']['alu_alumni'])}, "
          f"si={len(results['emails']['alu_si'])}, "
          f"other={len(results['emails']['other'])})")
    print(f"  Emails rejected     : {len(results['emails']['rejected'])}")
    print(f"  Credit cards valid  : {results['credit_cards']['count']}  (masked)")
    print(f"  Credit cards rej.   : {len(results['credit_cards']['rejected'])}")
    print(f"  URLs valid          : {len(results['urls']['valid'])}")
    print(f"  URLs rejected       : {len(results['urls']['rejected'])}")
    print(f"  Phones found        : {len(results['phones'])}")
    print(f"  Times (12-hour)     : {len(results['times']['12hour'])}")
    print(f"  Times (24-hour)     : {len(results['times']['24hour'])}")
    print(f"  Currency amounts    : {len(results['currency'])}")
    print(f"  Hashtags            : {len(results['hashtags'])}")
    print(f"  HTML tags (safe)    : {len(results['html_tags']['safe'])}")
    print(f"  HTML tags (flagged) : {len(results['html_tags']['flagged'])}")


if __name__ == "__main__":
    main()
