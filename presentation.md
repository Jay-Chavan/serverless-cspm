# Project Presentation: Serverless Cloud Security Posture Management (CSPM)

## 1. Introduction
Cloud Security Posture Management (CSPM) is a critical domain in modern cloud infrastructure, focusing on identifying and remediating misconfigurations and compliance risks. Cloud misconfigurations, such as leaving Amazon S3 buckets publicly accessible or unencrypted, remain the leading cause of data breaches.

This project implements a **Real-Time, Event-Driven CSPM Solution** leveraging AWS Serverless technologies and Open Policy Agent (OPA). Unlike traditional periodic scanning tools, our system detects security violations instantly as resources are created or modified, providing immediate visibility into the security posture.

## 2. Literature Survey & Gap Analysis

### Existing Tools
1.  **AWS Config & Security Hub**: Native AWS services.
    *   *Limit*: Can be expensive at scale; often has a latency (5-15 mins) between change and detection.
2.  **Prowler / ScoutSuite**: Open-source CLI auditing tools.
    *   *Limit*: Operate on a "scan" basis (scheduled or manual). They define "point-in-time" security, not real-time monitoring.
3.  **Commercial CSPM (e.g., Prisma Cloud, Wiz)**: Enterprise-grade suites.
    *   *Limit*: High licensing costs; black-box policy engines that can be hard to customize for specific organizational needs.

### Identify Gap
Most existing solutions suffer from one of three problems:
1.  **Latency**: Detection happens minutes or hours after a misconfiguration occurs.
2.  **Cost**: Continuous polling or enterprise licenses are expensive.
3.  **Rigidity**: Hard-coded compliance rules that are difficult to update or extend.

### Our Resolution
Our project resolves these gaps by building an **Event-Driven Architecture**:
*   **Real-Time**: Triggered immediately by AWS EventBridge events (e.g., `CreateBucket`, `PutBucketAcl`).
*   **Cost-Effective**: Uses AWS Lambda (pay-per-execution) and a lightweight OPA server, avoiding expensive continuous polling.
*   **Flexible Policy Engine**: Uses **Open Policy Agent (OPA)** with Rego, decoupling policy logic from application code. Rules can be updated without redeploying the infrastructure.

## 3. Project Objectives (Top 5)

1.  **Real-Time Detection**: Architect a system that detects security misconfigurations (e.g., Public S3 Buckets) within seconds of creation.
2.  **Policy-as-Code Implementation**: Decouple security logic using OPA and Rego, enabling dynamic and audit-friendly policy management.
3.  **Centralized Visualization**: Develop a user-friendly Dashboard to visualize security findings, risk levels, and compliance status in real-time.
4.  **End-to-End Automation**: Automate the entire pipeline from Event Capture (EventBridge) -> Analysis (OPA) -> Storage (MongoDB) -> Alerting.
5.  **Extensible Framework**: Design a modular architecture that can easily expand to support other AWS services (EC2, IAM, RDS) by adding new Rego rules and Lambda handlers.

## 4. Test Results & Validation

We successfully validated the system against critical security scenarios:

| Test Case | Scenario Description | Expected Outcome | Actual Result | Status |
| :--- | :--- | :--- | :--- | :--- |
| **TC-01** | **Public Bucket Creation**<br>User creates an S3 bucket with "Block Public Access" disabled. | System detects high-risk finding; Alert sent to Dashboard. | **Detected**: "High Risk - Public Access Enabled" | ✅ PASS |
| **TC-02** | **Secure Bucket (KMS)**<br>User creates a private bucket with KMS encryption enabled. | System marks resource as Compliant; No critical findings. | **Compliant**: No findings generated. | ✅ PASS |
| **TC-03** | **Security Drift**<br>User modifies a secure bucket to make it public. | System detects the configuration change event and triggers an alert. | **Detected**: Real-time alert on modification. | ✅ PASS |
| **TC-04** | **Resource Deletion**<br>User deletes a monitored bucket. | System cleans up stale findings from the dashboard. | **Verified**: Findings removed from DB. | ✅ PASS |

**Performance**: The average latency from "Resource Creation" to "Dashboard Alert" was observed to be **< 5 seconds**.

## 5. Conclusion
This project successfully demonstrates a modern, scalable approach to Cloud Security Posture Management. By combining the agility of Serverless computing with the flexibility of Policy-as-Code (OPA), we achieved a robust monitoring system that outperforms traditional periodic scanners in speed and cost-efficiency.

The solution provides:
*   **Immediate Visibility**: No more waiting for "next scan".
*   **Customizable Security**: Policies are just code.
*   **Operational Efficiency**: Automated tracking of security posture.

**Future Scope**:
*   Automated Remediation (e.g., auto-blocking public buckets).
*   Expansion to multi-cloud environments (Azure/GCP) using the same OPA policy engine.
