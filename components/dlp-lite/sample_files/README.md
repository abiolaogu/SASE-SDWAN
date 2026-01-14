# DLP-lite Sample Files

This directory contains safe sample files for testing DLP classifiers.

**IMPORTANT**: These files contain fake/test data only. Do not use real sensitive data.

## Files

- `test_ssn.txt` - Contains fake SSN patterns
- `test_credit_card.txt` - Contains fake credit card numbers (invalid Luhn)
- `test_api_keys.txt` - Contains fake API keys and tokens
- `test_mixed.txt` - Mixed content with various patterns

## Usage

```bash
dlp-lite scan --file sample_files/test_ssn.txt
dlp-lite scan --file sample_files/test_mixed.txt
```
