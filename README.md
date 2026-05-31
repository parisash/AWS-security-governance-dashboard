# AWS Security Governance Dashboard

A practical cloud security governance project that converts mock AWS security findings into risk scores, control mappings, remediation priorities and audit-ready evidence.

This project demonstrates how cloud security findings can be translated into meaningful GRC outputs for security analysts, GRC teams, cloud teams and decision-makers.

## Project Purpose

Cloud security tools often generate many findings, but security and governance teams need more than raw alerts. They need clear risk context, control mapping, ownership, remediation priority and evidence that can support audit readiness.

This project shows how AWS-style security findings can be transformed into:

* Risk-ranked security issues
* Control mappings
* Remediation priorities
* Evidence records
* Executive-ready reporting
* Audit-ready governance artefacts

## Why This Project Matters

This project is designed to reflect real industry workflows across:

* Cybersecurity GRC
* Cloud security governance
* Information security analysis
* Risk and compliance reporting
* Audit evidence preparation
* Security remediation tracking

It demonstrates the ability to connect technical security findings with business risk, control assurance and governance outcomes.

## Key Features

* Ingests mock AWS security findings
* Assigns risk scores based on severity, exposure and asset sensitivity
* Maps findings to security control areas
* Prioritises remediation actions
* Produces audit-ready evidence records
* Generates an executive summary report
* Supports practical security governance decision-making

## Example Use Case

A cloud security team receives findings from AWS security services such as Security Hub, Inspector or Macie.

Instead of leaving findings as technical alerts, this project converts them into a governance-ready format:

```text
Finding → Risk Score → Control Mapping → Remediation Priority → Evidence Record → Executive Report
```

## Example Security Finding

```text
Finding: S3 bucket allows public access
Severity: High
Asset Sensitivity: Sensitive data
Exposure: Internet-facing
Mapped Control: Access Control / Data Protection
Risk Priority: Critical
Recommended Action: Block public access, review bucket policy, validate encryption and document closure evidence
```

## Planned Repository Structure

```text
aws-security-governance-dashboard/
│
├── data/
│   ├── mock_aws_findings.csv
│   └── control_mapping.csv
│
├── src/
│   ├── risk_scoring.py
│   └── generate_report.py
│
├── reports/
│   └── executive_summary.md
│
├── screenshots/
│   └── dashboard_preview.png
│
├── README.md
├── requirements.txt
└── .gitignore
```

## Dataset

This project uses mock data only. No real organisation, client, cloud account or security finding data is included.

The mock dataset will include fields such as:

* Finding ID
* AWS service
* Finding title
* Severity
* Asset type
* Asset sensitivity
* Exposure level
* Control domain
* Remediation status
* Owner
* Evidence required
* Risk score

## Risk Scoring Logic

The project uses a simple scoring model:

```text
Risk Score = Severity Score × Exposure Score × Asset Sensitivity Score
```

Example scoring:

| Factor            | Example Values                 |
| ----------------- | ------------------------------ |
| Severity          | Low, Medium, High, Critical    |
| Exposure          | Internal, Restricted, Public   |
| Asset Sensitivity | Low, Moderate, High, Sensitive |

The final score is used to assign remediation priority.

## Control Mapping Areas

Findings are mapped to common cloud security and GRC control areas, such as:

* Access control
* Data protection
* Vulnerability management
* Logging and monitoring
* Asset management
* Configuration management
* Incident response readiness
* Third-party and privacy risk

## Project Outputs

This project generates practical governance-ready outputs from mock AWS security findings:

- `reports/risk_scored_findings.csv` — enriched findings with risk scores, remediation priority, SLA, control mapping and evidence status
- `reports/risk_summary.csv` — summary of findings by remediation priority and status
- `reports/executive_summary.md` — executive-style governance report for audit readiness and stakeholder reporting

The workflow demonstrates:

```text
Mock AWS Findings → Risk Scoring → Control Mapping → Remediation Priority → Evidence Register → Executive Report

## Tools and Technologies

* Python
* pandas
* CSV
* Markdown reporting
* Streamlit for dashboard visualisation

## How to Run

Clone the repository:

```bash
git clone https://github.com/YOUR-USERNAME/aws-security-governance-dashboard.git
cd aws-security-governance-dashboard
```

Create a virtual environment:

```bash
python -m venv venv
```

Activate the environment.

On Windows:

```bash
venv\Scripts\activate
```

On macOS/Linux:

```bash
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Run the risk scoring script:

```bash
python src/risk_scoring.py
```

Generate the report:

```bash
python src/generate_report.py
```

## Skills Demonstrated

This project demonstrates practical capability in:

* Cybersecurity GRC
* Cloud security governance
* Risk scoring
* Control mapping
* Security findings analysis
* Evidence register design
* Remediation prioritisation
* Executive reporting
* Python-based security analytics
* Audit-ready documentation

## Career Relevance

This project aligns with roles such as:

* Cybersecurity GRC Analyst
* Cybersecurity Analyst
* Information Security Analyst
* Cloud Security Analyst
* Risk and Compliance Analyst
* Data Privacy Analyst
* Security Governance Analyst

## Future Improvements

Planned improvements include:

* Add Streamlit dashboard
* Add visual risk charts
* Add ISO 27001 and NIST CSF mapping examples
* Add Essential Eight alignment
* Add remediation SLA tracking
* Add evidence quality status
* Add sample screenshots
* Add automated executive report generation

## Disclaimer

This project uses simulated data for portfolio and learning purposes. It does not contain real security findings, real AWS account data or confidential organisational information.

## Author

**Parisa Shojaei**

Cybersecurity GRC · Cloud Security · Privacy Governance · Risk Analytics · AI Assurance
Python · SQL · AWS · Jira
