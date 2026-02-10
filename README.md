# Serverless CSPM (Cloud Security Posture Management)

A serverless security monitoring tool that identifies misconfigurations in AWS resources (S3, KMS) and displays findings in a centralized dashboard.

## 🏗 Architecture Overview

The system consists of three main components:

1.  **Real-Time Monitoring (AWS Lambdas)**: Python-based Lambda functions (`s3-auditor`, `kms-auditor`) that trigger on resource events or scheduled scans to identify security risks.
2.  **Findings Dashboard Backend (Flask)**: A Python API that aggregates findings from MongoDB Atlas and provides data to the frontend.
3.  **Findings Dashboard Frontend (React + Vite)**: A modern web interface for viewing and managing security findings.

## 🚀 Quick Start

The project includes automation scripts for easy startup on Windows:

- **`run.bat`**: A simple batch file to bypass execution policies and start the project.
- **`start_project.ps1`**: The main PowerShell script that launches the backend and frontend in separate windows.

### Prerequisites

- **Python 3.9+** (Backend & Lambdas)
- **Node.js & npm** (Frontend)
- **AWS CLI** configured with appropriate permissions.
- **MongoDB Atlas** account (for persistent findings storage).
- **Terraform** (for infrastructure deployment).

## 🛠 Setup Instructions

### 1. MongoDB Atlas Configuration
- Create a cluster and database named `csmp_findings`.
- Ensure you have a connection string formatted as `mongodb+srv://...`.

### 2. Backend Setup (`/csmp-findings-dashboard/backend`)
- Copy `.env.example` to `.env` and fill in your `MONGO_URI`.
- Install dependencies: `pip install -r requirements.txt`.

### 3. Frontend Setup (`/csmp-findings-dashboard`)
- Install dependencies: `npm install`.

### 4. Infrastructure Deployment (`/real_time_monitoring/aws/terraform`)
- Configure your `terraform.tfvars` with MongoDB details.
- Run `terraform init` and `terraform apply`.

## ✨ Recent Changes

- **MongoDB Atlas Integration**: Replaced local storage with MongoDB Atlas for persistent, cloud-based findings.
- **Fixed Lambda Handlers**: Resolved "Unable to import module" errors in AWS Lambda.
- **Improved Startup Scripts**: Added `run.bat` and `start_project.ps1` for one-click environment startup.
- **Sample Data Population**: Backend now includes an endpoint (`/api/populate-sample-data`) to seed the dashboard for testing.

---
*For component-specific details, see the READMEs in the respective subdirectories.*
