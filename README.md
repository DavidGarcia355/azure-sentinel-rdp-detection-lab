# Azure Sentinel RDP Detection Lab

This project simulates a basic SOC (Security Operations Center) detection pipeline by configuring Microsoft Sentinel to monitor a Windows 10 Pro virtual machine for RDP login activity.

---

## Tools & Services Used

- Microsoft Azure (Free Trial)
- Windows 10 Pro Virtual Machine (Azure)
- Microsoft Sentinel (SIEM)
- Log Analytics Workspace
- Data Connectors (Windows Security Events)
- Kusto Query Language (KQL)

---

## Setup Process

### 1. VM Creation
- Created a new Azure VM using the Windows 10 Pro image.
- Enabled RDP (Remote Desktop Protocol).
- Left all other settings at default.
- Screenshot: VM Overview Page

### 2. Deploying Microsoft Sentinel
- Created a Log Analytics Workspace.
- Installed Microsoft Sentinel into the workspace.
- Screenshot: Sentinel Overview Panel

### 3. Ingesting Logs
- Used Data Connectors to add Windows Security Events.
- Configured a Data Collection Rule (DCR) to pull security logs from the VM.
- Screenshot: Data Connector Setup

### 4. Writing Detection Rule
- Created a Scheduled Analytics Rule using the following custom KQL:

```kql
SecurityEvent
| where EventID == 4624
| where Account !contains "SYSTEM"
| where LogonType == 10
