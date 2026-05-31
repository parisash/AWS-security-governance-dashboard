# AWS Security Governance Executive Summary

## Overview

This report summarises simulated AWS security findings and translates them into governance-ready outputs, including risk scores, remediation priorities, control domains, evidence expectations and ownership visibility.

The purpose of this report is to demonstrate how technical cloud security findings can be converted into practical GRC evidence for audit readiness, remediation planning and stakeholder reporting.

## Key Metrics

| Metric | Value |
|---|---:|
| Total findings reviewed | 15 |
| Open findings | 12 |
| In-progress findings | 3 |
| Critical priority findings | 2 |
| High priority findings | 4 |

## Priority Summary

| remediation_priority   |   finding_count |
|:-----------------------|----------------:|
| Medium                 |               5 |
| High                   |               4 |
| Low                    |               4 |
| Critical               |               2 |

## Control Domain Summary

| control_domain                 |   finding_count |
|:-------------------------------|----------------:|
| Data Protection                |               4 |
| Identity and Access Management |               2 |
| Container Security             |               1 |
| Database Security              |               1 |
| Encryption and Key Management  |               1 |
| Logging and Monitoring         |               1 |
| Network Security               |               1 |
| Serverless Security            |               1 |
| Threat Detection               |               1 |
| Transport Security             |               1 |
| Vulnerability Management       |               1 |

## Owner Summary

| owner                     |   finding_count |
|:--------------------------|----------------:|
| Cloud Security Team       |               3 |
| Security Operations Team  |               2 |
| Data Governance Team      |               2 |
| Infrastructure Team       |               2 |
| Identity and Access Team  |               2 |
| Application Security Team |               1 |
| Cloud Operations Team     |               1 |
| Application Team          |               1 |
| Database Team             |               1 |

## Top 5 Risk-Ranked Findings

| finding_id   | source_tool   | aws_service    | finding_title                                           | severity   | exposure   | asset_sensitivity   |   risk_score | remediation_priority   | target_sla   | owner                |
|:-------------|:--------------|:---------------|:--------------------------------------------------------|:-----------|:-----------|:--------------------|-------------:|:-----------------------|:-------------|:---------------------|
| F-001        | Security Hub  | S3             | S3 bucket allows public read access                     | Critical   | Public     | Sensitive           |           48 | Critical               | 7 days       | Cloud Security Team  |
| F-003        | Inspector     | EC2            | EC2 instance has critical vulnerability                 | Critical   | Public     | High                |           36 | Critical               | 7 days       | Infrastructure Team  |
| F-004        | Macie         | S3             | Sensitive personal data detected in unencrypted storage | Critical   | Restricted | Sensitive           |           32 | High                   | 14 days      | Data Governance Team |
| F-006        | Security Hub  | Security Group | Security group allows inbound SSH from internet         | High       | Public     | High                |           27 | High                   | 14 days      | Cloud Security Team  |
| F-014        | Security Hub  | ELB            | Load balancer does not enforce HTTPS                    | High       | Public     | High                |           27 | High                   | 14 days      | Infrastructure Team  |

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
