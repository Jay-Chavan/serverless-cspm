# CSPM Manual Demonstration Guide

This guide walks you through a manual demonstration of the Cloud Security Posture Management (CSPM) system.
It simulates real-world AWS events (bucket creation, deletion) triggering the security audit pipeline, generating findings, and reflecting them in real-time on the CSPM Dashboard.

**Note**: Due to provisional OPA latency, the detection logic currently uses a simulated OPA response within the test scripts to guarantee immediate feedback for this demo. The database and dashboard integration is fully live.

## Prerequisites

1.  **Backend Running**: Ensure the Flask backend is running (Port 5000).
2.  **Frontend Running**: Ensure the Vite frontend is running (Port 5173).
3.  **Dashboard Access**: Open your browser to `http://localhost:5173`.

---

## Demo Scenario 1: Real-World Public Bucket Detection (AWS Console)

**Objective**: Manually create a risky bucket in the AWS Console and verify the CSPM detecting it.

1.  **Create Bucket in AWS**:
    *   Log in to your **AWS Console**.
    *   Go to **S3** -> **Create bucket**.
    *   **Bucket name**: `jay-public-demo-bucket-123` (Ensure it's unique).
    *   **Region**: `ap-south-1` (Asia Pacific (Mumbai)).
    *   **Uncheck "Block all public access"** (Acknowledge the warning).
    *   Click **Create bucket**.

2.  **Verify Detection**:
    *   Wait ~1-2 minutes for CloudTrail -> EventBridge -> Lambda processing.
    *   Refresh your CSPM **Dashboard**.
    *   **Result**: A new **High/Critical** finding for `jay-public-demo-bucket-123` will appear.

---

## Demo Scenario 2: High-Risk Public Bucket Detection (Simulated)

**Objective**: Simulate the creation of a publicly accessible S3 bucket and verify the system detects it as "High Risk".

1.  **Check Dashboard**:
    *   Navigate to the **Dashboard** or **Findings** page.
    *   Confirm that there are **0 active findings** for `test-public-bucket`.

2.  **Trigger Detection Event**:
    *   Open a new terminal in VS Code.
    *   Run the detection script:
        ```powershell
        python tests/test_case_1_public_bucket.py
        ```
    *   **What happens**: reliable simulation of an S3 `CreateBucket` event for a bucket named `test-public-bucket`. The system audits it (simulating OPA "High Risk" decision due to public access) and actively pushes the finding to MongoDB.

3.  **Verify in Dashboard**:
    *   Refresh the Dashboard page.
    *   **Result**: You should see a new **High Severity** finding for `test-public-bucket`.
    *   **Details**: Click the finding to see details like "S3 Bucket Public Access Enabled".

---

## Demo Scenario 2: Secure Bucket Compliance (Noise Reduction)

**Objective**: Simulate the creation of a secure, KMS-encrypted bucket to prove the system does *not* generate false positives.

1.  **Trigger Safe Event**:
    *   Run the secure bucket script:
        ```powershell
        python tests/test_case_2_kms_bucket.py
        ```
    *   **What happens**: Simulates creation of `test-kms-bucket` with full security (Private, KMS Encrypted). The OPA logic evaluates this as "Compliant".

2.  **Verify in Dashboard**:
    *   Refresh the Dashboard.
    *   **Result**: **No new finding** should appear for `test-kms-bucket`. The system correctly filtered out the complaint resource.

---

## Demo Scenario 3: Remediation & Cleanup

**Objective**: Simulate the deletion of the risky bucket and verify the finding is automatically resolved/removed.

1.  **Trigger Deletion Event**:
    *   Run the cleanup script:
        ```powershell
        python tests/test_case_3_delete_bucket.py
        ```
    *   **What happens**: Simulates an S3 `DeleteBucket` event for `test-public-bucket`. The Lambda processes this and removes valid findings from the database.

2.  **Verify in Dashboard**:
    *   Refresh the Dashboard.
    *   **Result**: The finding for `test-public-bucket` should **disappear**.

---

## Troubleshooting

-   **Dashboard not updating?**: Ensure the backend terminal shows `200 OK` for `/api/findings` requests.
-   **Script fails?**: Ensure you are in `d:\Projects\CSPM\serverless-cspm` and your Python environment is active.
