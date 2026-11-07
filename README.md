# AI Prompt Injection Detection

A Python-based cybersecurity project that detects potential prompt injection attempts using rule-based pattern matching, assigns risk scores, logs suspicious activity, and generates security reports.

This project explores how security monitoring techniques can be applied to AI security threats.

## Project Overview

Prompt injection is a security risk in which malicious input attempts to manipulate an AI system's instructions or behavior.

This project implements a simple detection engine to identify predefined suspicious patterns and classify them based on risk.

The project is designed as a practical learning initiative focused on AI security, Python, and security monitoring.

## Features

- Rule-based prompt injection detection
- Detection of instruction override attempts
- Detection of sensitive information disclosure attempts
- Detection of security bypass attempts
- Risk score calculation
- Severity classification
- Security event logging
- Security report generation
- CSV report export
- Automated unit tests

## Detection Categories

| Category | Description |
|---|---|
| Instruction Override | Attempts to manipulate or override existing instructions |
| Data Exfiltration | Attempts to extract confidential or protected information |
| Security Bypass | Attempts to bypass security controls or safety mechanisms |

## Risk Classification

The detector assigns risk scores based on predefined detection patterns.

| Risk Score | Severity |
|---|---|
| 0–29 | LOW |
| 30–69 | MEDIUM |
| 70–100 | HIGH |

The risk score is capped at 100.

## Technologies Used

- Python
- Regular expressions and pattern matching
- Logging
- CSV reporting
- Unit testing
- Git and GitHub

## Project Structure

```text
AI-Cybersecurity/
│
├── prompt_injection_detector.py
├── day3_llm_security.py
├── security_report.py
├── test_prompt_injection_detector.py
├── README.md
└── .gitignore
```

## Installation

Clone the repository:

```bash
git clone https://github.com/Rohith1402/AI-Prompt-Injection-Detection.git
```

Navigate to the project directory:

```bash
cd AI-Prompt-Injection-Detection
```

Create a virtual environment:

```bash
python3 -m venv .venv
```

Activate the virtual environment on macOS or Linux:

```bash
source .venv/bin/activate
```

## Usage

Run the prompt injection detector:

```bash
python3 prompt_injection_detector.py
```

Run the security report:

```bash
python3 security_report.py
```

Run the automated tests:

```bash
python3 -m unittest test_prompt_injection_detector.py
```

## Security Monitoring

The project uses Python logging to record detected suspicious activity.

Security reports summarize detected events, risk scores, severity levels, and detection categories.

CSV output can be used for further analysis and security monitoring.

## Testing

Automated unit tests are included to validate the detection engine.

Test scenarios include:

- Normal input
- Instruction override attempts
- Sensitive information disclosure attempts
- Security bypass attempts
- Case-insensitive detection
- Risk score calculation

## Limitations

- Detection is based on predefined patterns.
- Unknown or obfuscated prompt injection attempts may not be detected.
- Risk scores are rule-based and are not machine-learning predictions.
- Detection results do not guarantee that an input is safe or malicious.
- The project does not currently implement a live LLM integration.

## Future Improvements

- Expand prompt injection detection patterns
- Improve detection accuracy
- Add additional security test cases
- Integrate official MITRE ATLAS technique references
- Develop a security monitoring dashboard
- Explore LLM-based security analysis

## Disclaimer

This project is developed for educational purposes and cybersecurity learning.

It is not intended to replace enterprise security monitoring or production-grade AI security controls.

## Author

Rohith

GitHub: [Rohith1402](https://github.com/Rohith1402)