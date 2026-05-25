"""Regex Data Extraction Tool — extracts and validates emails, cards, URLs, phones, times, currency, hashtags, and HTML tags."""

import re
import json
from pathlib import Path

# ── Security ─────────────────────────────────────────────────────────────────

_DANGEROUS = ["javascript:", "data:", "file:/", "drop table", "<script", "../", "..\\"]

def is_dangerous(text):
    t = text.lower()
    return any(m in t for m in _DANGEROUS)

def _ctx(text, start, end, r=120):
    return text[max(0, start - r): min(len(text), end + r)]

# ── Emails ────────────────────────────────────────────────────────────────────

def extract_emails(text):
    pat = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
    out = {"alu_official": [], "alu_alumni": [], "alu_si": [], "other": [], "rejected": []}
    for m in pat.finditer(text):
        addr = m.group()
        if is_dangerous(addr) or is_dangerous(_ctx(text, m.start(), m.end())):
            out["rejected"].append(addr)
            continue
        d = addr.split("@")[-1].lower()
        bucket = ("alu_official" if d == "alueducation.com"
                  else "alu_alumni" if d == "alumni.alueducation.com"
                  else "alu_si" if d == "si.alueducation.com"
                  else "other")
        out[bucket].append(addr)
    return out

# ── Credit cards ──────────────────────────────────────────────────────────────

def _luhn(digits):
    total = sum(
        (n * 2 - 9 if n * 2 > 9 else n * 2) if i % 2 == 1 else n
        for i, n in enumerate(int(c) for c in reversed(digits))
    )
    return total % 10 == 0

def _mask(d):
    groups = ["****"] * (len(d[:-4]) // 4 + bool(len(d[:-4]) % 4))
    return " ".join(groups) + " " + d[-4:]

def extract_credit_cards(text):
    cards, rejected = [], []
    for raw in re.findall(r"\b(?:\d[ -]?){13,19}\b", text):
        digits = re.sub(r"\D", "", raw)
        if is_dangerous(raw) or not (13 <= len(digits) <= 19) or len(set(digits)) == 1 or not _luhn(digits):
            rejected.append("REDACTED")
        else:
            cards.append(_mask(digits))
    return {"masked": cards, "count": len(cards), "rejected": rejected}

# ── URLs ──────────────────────────────────────────────────────────────────────

def extract_urls(text):
    valid, rejected = [], []
    for url in re.findall(r"\bhttps?://[^\s'\"<>]+", text, re.IGNORECASE):
        (rejected if is_dangerous(url) else valid).append(url)
    return {"valid": valid, "rejected": rejected}

# ── Phones ────────────────────────────────────────────────────────────────────

def extract_phones(text):
    pats = [
        re.compile(r"\+\d{1,3}[ -]?(?:\(\d{1,4}\)[ -]?)?\d{2,4}[ -]?\d{2,4}(?:[ -]?\d{2,4})?"),
        re.compile(r"\(\d{3,4}\)[ -]?\d{3,4}[ -]?\d{4}"),
        re.compile(r"\b\d{3}[ -]\d{3,4}[ -]\d{4}\b"),
    ]
    candidates = {m.strip() for p in pats for m in p.findall(text)}
    phones = [p for p in candidates
              if (d := re.sub(r"\D", "", p)) and len(d) >= 7 and d.lstrip("0")]
    phones.sort(key=len, reverse=True)
    final = []
    for p in phones:
        if not any(p in longer for longer in final):
            final.append(p)
    return sorted(final)

# ── Times ─────────────────────────────────────────────────────────────────────

def extract_times(text):
    t12 = re.findall(r"\b(?:1[0-2]|0?[1-9]):[0-5][0-9]\s?(?:AM|PM|am|pm)\b", text)
    t24 = re.findall(r"\b(?:[01]?\d|2[0-3]):[0-5][0-9]\b", text)
    bare = {t.split()[0] for t in t12}
    return {"12hour": t12, "24hour": [t for t in t24 if t not in bare]}

# ── Currency / Hashtags / HTML ────────────────────────────────────────────────

def extract_currency(text):
    return re.findall(r"(?:\$|€|£)\s?\d{1,3}(?:,\d{3})*(?:\.\d{2})?", text)

def extract_hashtags(text):
    return [h for h in re.findall(r"#[A-Za-z0-9_]+", text) if re.search(r"[A-Za-z]", h)]

def extract_html_tags(text):
    safe, flagged = [], []
    for tag in re.findall(r"</?[A-Za-z0-9\-]+(?:\s+[^>]+)?>", text):
        (flagged if "script" in tag.lower() or is_dangerous(tag) else safe).append(tag)
    return {"safe": safe, "flagged": flagged}

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print("=== Regex Data Extraction Tool ===\n")
    raw = (Path(__file__).parent / ".." / "input" / "raw-text.text").read_text(encoding="utf-8")
    print(f"Input loaded: {len(raw)} characters\n")
    if is_dangerous(raw):
        print("WARNING: input contains suspicious patterns — results include rejection detail.\n")

    r = {
        "emails":       extract_emails(raw),
        "credit_cards": extract_credit_cards(raw),
        "urls":         extract_urls(raw),
        "phones":       extract_phones(raw),
        "times":        extract_times(raw),
        "currency":     extract_currency(raw),
        "hashtags":     extract_hashtags(raw),
        "html_tags":    extract_html_tags(raw),
    }

    out = Path(__file__).parent / ".." / "output" / "sample-output.json"
    out.write_text(json.dumps(r, indent=2), encoding="utf-8")
    print(f"Results written to: {out.resolve()}\n")

    e = r["emails"]
    email_total = sum(len(v) for k, v in e.items() if k != "rejected")
    print("--- EXTRACTION SUMMARY ---")
    print(f"  Emails found        : {email_total}  (official={len(e['alu_official'])}, alumni={len(e['alu_alumni'])}, si={len(e['alu_si'])}, other={len(e['other'])})")
    print(f"  Emails rejected     : {len(e['rejected'])}")
    print(f"  Credit cards valid  : {r['credit_cards']['count']}  (masked)")
    print(f"  Credit cards rej.   : {len(r['credit_cards']['rejected'])}")
    print(f"  URLs valid          : {len(r['urls']['valid'])}")
    print(f"  URLs rejected       : {len(r['urls']['rejected'])}")
    print(f"  Phones found        : {len(r['phones'])}")
    print(f"  Times (12-hour)     : {len(r['times']['12hour'])}")
    print(f"  Times (24-hour)     : {len(r['times']['24hour'])}")
    print(f"  Currency amounts    : {len(r['currency'])}")
    print(f"  Hashtags            : {len(r['hashtags'])}")
    print(f"  HTML tags (safe)    : {len(r['html_tags']['safe'])}")
    print(f"  HTML tags (flagged) : {len(r['html_tags']['flagged'])}")


if __name__ == "__main__":
    main()
