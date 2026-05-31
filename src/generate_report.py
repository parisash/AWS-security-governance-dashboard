from pathlib import Path
import pandas as pd


BASE_DIR = Path(__file__).resolve().parent.parent

RISK_SCORED_FILE = BASE_DIR / "reports" / "risk_scored_findings.csv"
REPORTS_DIR = BASE_DIR / "reports"
EXECUTIVE_REPORT_FILE = REPORTS_DIR / "executive_summary.md"


def load_risk_scored_findings() -> pd.DataFrame:
    if not RISK_SCORED_FILE.exists():
        raise FileNotFoundError(
            "risk_scored_findings.csv was not found. "
            "Please run 'py src/risk_scoring.py' first."
        )

    return pd.read_csv(RISK_SCORED_FILE)


def create_markdown_table(df: pd.DataFrame, columns: list[str]) -> str:
    selected = df[columns].copy()
    return selected.to_markdown(index=False)


def generate_executive_report(df: pd.DataFrame) -> str:
    total_findings = len(df)
    open_findings = len(df[df["status"] == "Open"])
    in_progress_findings = len(df[df["status"] == "In Progress"])
    critical_priority = len(df[df["remediation_priority"] == "Critical"])
    high_priority = len(df[df["remediation_priority"] == "High"])

    top_findings = df.sort_values(by="risk_score", ascending=False).head(5)

    priority_summary = (
        df.groupby("remediation_priority")
        .size()
        .reset_index(name="finding_count")
        .sort_values(by="finding_count", ascending=False)
    )

    control_domain_summary = (
        df.groupby("control_domain")
        .size()
        .reset_index(name="finding_count")
        .sort_values(by="finding_count", ascending=False)
    )

    owner_summary = (
        df.groupby("owner")
        .size()
        .reset_index(name="finding_count")
        .sort_values(by="finding_count", ascending=False)
    )

    report = f"""# AWS Security Governance Executive Summary

## Overview

This report summarises simulated AWS security findings and translates them into governance-ready outputs, including risk scores, remediation priorities, control domains, evidence expectations and ownership visibility.

The purpose of this report is to demonstrate how technical cloud security findings can be converted into practical GRC evidence for audit readiness, remediation planning and stakeholder reporting.

## Key Metrics

| Metric | Value |
|---|---:|
| Total findings reviewed | {total_findings} |
| Open findings | {open_findings} |
| In-progress findings | {in_progress_findings} |
| Critical priority findings | {critical_priority} |
| High priority findings | {high_priority} |

## Priority Summary

{create_markdown_table(priority_summary, ["remediation_priority", "finding_count"])}

## Control Domain Summary

{create_markdown_table(control_domain_summary, ["control_domain", "finding_count"])}

## Owner Summary

{create_markdown_table(owner_summary, ["owner", "finding_count"])}

## Top 5 Risk-Ranked Findings

{create_markdown_table(
    top_findings,
    [
        "finding_id",
        "source_tool",
        "aws_service",
        "finding_title",
        "severity",
        "exposure",
        "asset_sensitivity",
        "risk_score",
        "remediation_priority",
        "target_sla",
        "owner",
    ],
)}

## Governance Interpretation

The highest-risk findings are prioritised based on severity, exposure and asset sensitivity.

Findings involving public exposure, sensitive data, missing logging, missing encryption or critical vulnerabilities require faster remediation and stronger closure evidence.

This project demonstrates a practical security governance workflow:

AWS Finding -> Risk Score -> Control Domain -> Remediation Priority -> Evidence Requirement -> Executive Report

## Recommended Actions

1. Prioritise all Critical and High findings for remediation.
2. Confirm ownership for each open finding.
3. Validate closure evidence before marking findings as complete.
4. Review control domains with repeated findings to identify systemic weaknesses.
5. Maintain evidence records for audit readiness and risk-based decision-making.

## Disclaimer

This report is generated from simulated AWS security findings for portfolio and learning purposes. It does not contain real AWS account data, client data or confidential security information.
"""

    return report


def save_report(report: str) -> None:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    EXECUTIVE_REPORT_FILE.write_text(report, encoding="utf-8")
    print(f"Executive report generated: {EXECUTIVE_REPORT_FILE}")


def main() -> None:
    findings = load_risk_scored_findings()
    report = generate_executive_report(findings)
    save_report(report)


if __name__ == "__main__":
    main()
