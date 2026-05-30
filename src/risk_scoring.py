from pathlib import Path
import pandas as pd


BASE_DIR = Path(__file__).resolve().parent.parent

FINDINGS_FILE = BASE_DIR / "data" / "mock_aws_findings.csv"
CONTROL_MAPPING_FILE = BASE_DIR / "data" / "control_mapping.csv"

REPORTS_DIR = BASE_DIR / "reports"
RISK_SCORED_OUTPUT = REPORTS_DIR / "risk_scored_findings.csv"
RISK_SUMMARY_OUTPUT = REPORTS_DIR / "risk_summary.csv"


SEVERITY_SCORE = {
    "Low": 1,
    "Medium": 2,
    "High": 3,
    "Critical": 4,
}

EXPOSURE_SCORE = {
    "Internal": 1,
    "Restricted": 2,
    "Public": 3,
}

ASSET_SENSITIVITY_SCORE = {
    "Low": 1,
    "Moderate": 2,
    "High": 3,
    "Sensitive": 4,
}


def validate_required_columns(df: pd.DataFrame, required_columns: list[str], file_name: str) -> None:
    missing_columns = [column for column in required_columns if column not in df.columns]

    if missing_columns:
        raise ValueError(
            f"{file_name} is missing required columns: {', '.join(missing_columns)}"
        )


def load_findings() -> pd.DataFrame:
    if not FINDINGS_FILE.exists():
        raise FileNotFoundError(f"File not found: {FINDINGS_FILE}")

    findings = pd.read_csv(FINDINGS_FILE)

    required_columns = [
        "finding_id",
        "source_tool",
        "aws_service",
        "finding_title",
        "severity",
        "asset_type",
        "asset_id",
        "asset_sensitivity",
        "exposure",
        "status",
        "owner",
        "evidence_required",
        "recommended_action",
    ]

    validate_required_columns(findings, required_columns, "mock_aws_findings.csv")

    return findings


def load_control_mapping() -> pd.DataFrame:
    if not CONTROL_MAPPING_FILE.exists():
        raise FileNotFoundError(f"File not found: {CONTROL_MAPPING_FILE}")

    control_mapping = pd.read_csv(CONTROL_MAPPING_FILE)

    required_columns = [
        "aws_service",
        "control_domain",
        "control_objective",
        "iso_27001_mapping",
        "nist_csf_mapping",
        "essential_eight_mapping",
        "evidence_examples",
        "governance_notes",
    ]

    validate_required_columns(control_mapping, required_columns, "control_mapping.csv")

    return control_mapping


def calculate_risk_score(row: pd.Series) -> int:
    severity = SEVERITY_SCORE.get(row["severity"], 1)
    exposure = EXPOSURE_SCORE.get(row["exposure"], 1)
    sensitivity = ASSET_SENSITIVITY_SCORE.get(row["asset_sensitivity"], 1)

    return severity * exposure * sensitivity


def assign_priority(risk_score: int) -> str:
    if risk_score >= 36:
        return "Critical"
    if risk_score >= 18:
        return "High"
    if risk_score >= 8:
        return "Medium"
    return "Low"


def assign_target_sla(priority: str) -> str:
    sla_mapping = {
        "Critical": "7 days",
        "High": "14 days",
        "Medium": "30 days",
        "Low": "60 days",
    }

    return sla_mapping.get(priority, "30 days")


def assign_evidence_status(status: str) -> str:
    if status == "Closed":
        return "Evidence complete"
    if status == "In Progress":
        return "Evidence pending validation"
    return "Evidence required"


def enrich_findings(findings: pd.DataFrame, control_mapping: pd.DataFrame) -> pd.DataFrame:
    findings = findings.copy()

    findings["severity_score"] = findings["severity"].map(SEVERITY_SCORE).fillna(1).astype(int)
    findings["exposure_score"] = findings["exposure"].map(EXPOSURE_SCORE).fillna(1).astype(int)
    findings["asset_sensitivity_score"] = (
        findings["asset_sensitivity"].map(ASSET_SENSITIVITY_SCORE).fillna(1).astype(int)
    )

    findings["risk_score"] = findings.apply(calculate_risk_score, axis=1)
    findings["remediation_priority"] = findings["risk_score"].apply(assign_priority)
    findings["target_sla"] = findings["remediation_priority"].apply(assign_target_sla)
    findings["evidence_status"] = findings["status"].apply(assign_evidence_status)

    enriched_findings = findings.merge(
        control_mapping,
        on="aws_service",
        how="left",
    )

    enriched_findings["control_domain"] = enriched_findings["control_domain"].fillna(
        "Unmapped Control Domain"
    )

    enriched_findings["governance_notes"] = enriched_findings["governance_notes"].fillna(
        "No control mapping available. Manual review required."
    )

    return enriched_findings


def create_summary(enriched_findings: pd.DataFrame) -> pd.DataFrame:
    summary = (
        enriched_findings
        .groupby(["remediation_priority", "status"], dropna=False)
        .size()
        .reset_index(name="finding_count")
        .sort_values(
            by=["remediation_priority", "status"],
            ascending=[True, True],
        )
    )

    priority_order = {
        "Critical": 1,
        "High": 2,
        "Medium": 3,
        "Low": 4,
    }

    summary["priority_order"] = summary["remediation_priority"].map(priority_order)
    summary = summary.sort_values(by=["priority_order", "status"])
    summary = summary.drop(columns=["priority_order"])

    return summary


def print_dashboard_summary(enriched_findings: pd.DataFrame) -> None:
    total_findings = len(enriched_findings)
    open_findings = len(enriched_findings[enriched_findings["status"] == "Open"])
    in_progress_findings = len(enriched_findings[enriched_findings["status"] == "In Progress"])
    critical_findings = len(
        enriched_findings[enriched_findings["remediation_priority"] == "Critical"]
    )
    high_findings = len(
        enriched_findings[enriched_findings["remediation_priority"] == "High"]
    )

    print("\nAWS Security Governance Dashboard")
    print("=" * 40)
    print(f"Total findings reviewed: {total_findings}")
    print(f"Open findings: {open_findings}")
    print(f"In-progress findings: {in_progress_findings}")
    print(f"Critical priority findings: {critical_findings}")
    print(f"High priority findings: {high_findings}")

    print("\nTop 5 risk-ranked findings")
    print("-" * 40)

    top_findings = (
        enriched_findings
        .sort_values(by="risk_score", ascending=False)
        .head(5)
    )

    columns_to_show = [
        "finding_id",
        "source_tool",
        "aws_service",
        "finding_title",
        "severity",
        "exposure",
        "asset_sensitivity",
        "risk_score",
        "remediation_priority",
        "owner",
        "target_sla",
    ]

    print(top_findings[columns_to_show].to_string(index=False))


def save_reports(enriched_findings: pd.DataFrame, summary: pd.DataFrame) -> None:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    enriched_findings.to_csv(RISK_SCORED_OUTPUT, index=False)
    summary.to_csv(RISK_SUMMARY_OUTPUT, index=False)

    print("\nReports generated successfully:")
    print(f"- {RISK_SCORED_OUTPUT}")
    print(f"- {RISK_SUMMARY_OUTPUT}")


def main() -> None:
    findings = load_findings()
    control_mapping = load_control_mapping()

    enriched_findings = enrich_findings(findings, control_mapping)
    summary = create_summary(enriched_findings)

    print_dashboard_summary(enriched_findings)
    save_reports(enriched_findings, summary)


if __name__ == "__main__":
    main()
