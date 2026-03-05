# AI Guardian — AI Security & Governance Assessment Toolkit

A comprehensive toolkit for assessing AI system security, conducting red team testing, classifying risk, and mapping governance compliance to NIST AI RMF, EU AI Act, and ISO 42001.

## Overview

AI Guardian enables organizations to:

- **Assess** AI systems against major governance frameworks
- **Red Team** AI models with structured attack scenarios (prompt injection, jailbreaking, data extraction)
- **Classify Risk** using automated risk scoring with business impact analysis
- **Map Compliance** across NIST AI RMF, EU AI Act, ISO 42001, and OWASP Top 10 for LLMs
- **Generate Reports** with findings, remediation guidance, and executive summaries

## Features

### Governance Framework Assessment
- **NIST AI RMF** — full coverage of Govern, Map, Measure, Manage functions
- **EU AI Act** — risk classification and compliance requirements
- **ISO 42001** — AI management system controls
- **OWASP Top 10 for LLMs** — common vulnerability assessment

### Red Team Testing
- Interactive red team console for AI model testing
- Pre-built attack library (prompt injection, jailbreaking, data extraction, bias probing)
- Session tracking with finding severity classification
- Structured output for audit documentation

### Risk Classification
- Automated risk scoring based on AI system characteristics
- Business impact analysis with likelihood/severity matrices
- Risk treatment recommendations

### Reporting
- HTML executive reports with compliance dashboards
- Markdown reports for documentation
- JSON export for GRC platform integration

## Installation

```bash
git clone https://github.com/atkens4real2000-sudo/AI-Guardian-Security-Governance.git
cd AI-Guardian-Security-Governance

pip install -r requirements.txt
```

**Requirements:**
- Python 3.8+

## Usage

### Interactive Mode

```bash
python3 guardian.py
```

### Command Line

```bash
# New assessment with governance documentation
python3 guardian.py --new "ChatBot v3" --org "Your Organization" --docs

# Assessment with specific framework
python3 guardian.py --new "AI Model" --org "Your Org" --framework nist-ai-rmf
```

### Red Team Console

```bash
python3 red_team_console.py
```

Launches an interactive session for testing AI models against structured attack scenarios.

## Project Structure

```
AI_Guardian/
├── guardian.py             # Main CLI application
├── assessment_engine.py    # Core assessment logic
├── ai_frameworks.py        # Governance framework definitions
├── governance_mapper.py    # Cross-framework compliance mapping
├── risk_classifier.py      # AI risk classification engine
├── red_team_engine.py      # Red team testing engine
├── red_team_console.py     # Interactive red team console
├── attack_library.json     # Pre-built attack scenarios
├── llm_connectors.py       # LLM API integrations
├── report_generators.py    # HTML, Markdown, JSON reporting
└── requirements.txt        # Python dependencies
```

## Frameworks Supported

| Framework | Coverage | Focus |
|-----------|----------|-------|
| NIST AI RMF 1.0 | Full | Risk management lifecycle |
| EU AI Act | Full | Risk classification & compliance |
| ISO 42001 | Full | AI management system |
| OWASP Top 10 for LLMs | Full | Common AI vulnerabilities |

## Disclaimer

This toolkit is designed for **authorized security assessment and governance evaluation**. Red team testing should only be performed on AI systems you own or have explicit authorization to test.

## Author

**Akintade Akinokun**
- LinkedIn: [linkedin.com/in/akintadeakins](https://linkedin.com/in/akintadeakins)
- GitHub: [github.com/atkens4real2000-sudo](https://github.com/atkens4real2000-sudo)

## License

MIT License
