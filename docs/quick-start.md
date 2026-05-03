# Quick Start

## First Run

1. Launch VanGuard (as Administrator/root)
2. Navigate to **Configuration** (option 8)
3. Create a new case — all evidence will be stored under `output/{case_id}/`
4. Set your analyst name and organisation
5. Download required tools via **Tool Management**

## Common Workflows

### Local Quick Triage
1. Select **Quick Triage** (option 4)
2. Choose **Local Quick Triage**
3. Wait for collection to complete
4. View results in `output/{case_id}/triage/`

### Deploy Velociraptor
1. Select **Velociraptor Operations** (option 1)
2. Choose **Initialize Server** to generate configs and start the server
3. Choose **Generate Client Package** to create a deployable agent
4. Deploy to endpoints via **Deploy Agent** (WinRM, SSH, or PSExec)
5. Access the web UI via **Launch Web UI**

### Remote Threat Hunt
1. Select **Remote Operations** (option 6)
2. Add targets (hostname, IP, credentials)
3. Select **Remote Hunt** to scan for threats across endpoints
4. Results are collected and registered as case evidence

### Generate Report
1. Select **Analysis & Reporting** (option 7)
2. Choose **Generate Report** for an HTML incident report
3. Choose **Build Timeline** for a super-timeline CSV

## Air-Gapped Usage

VanGuard works fully offline. Pre-download tools and rules while connected, then transfer the entire VanGuard directory to the air-gapped environment via USB.
