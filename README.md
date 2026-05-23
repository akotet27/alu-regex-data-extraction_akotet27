# alu-regex-data-extraction_akotet27

This project extracts structured data from messy raw text using regular expressions
and demonstrates safe handling of potentially malicious inputs.

How to run

From the repository root, run:

```bash
python src/main.py
```

Output

- `output/sample-output.json` will contain the extracted results (emails, masked
	credit cards, URLs, phones, times, currency, hashtags, HTML tags).

Notes

- The script includes ALU-specific email categorization (official, alumni, SI).
- Sensitive values (credit cards) are masked in the output. Suspicious inputs
	(javascript:, data:, SQL injection patterns) are rejected and listed in the
	`rejected` sections of the JSON output.

Files

- `input/raw-text.text`: sample messy input log
- `src/main.py`: extraction and validation logic
- `output/sample-output.json`: generated sample output

Author: akotet27