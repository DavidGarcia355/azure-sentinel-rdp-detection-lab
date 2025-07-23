# azure-sentinel-rdp-detection-lab

# Azure Sentinel RDP Detection Lab

## Overview
This project demonstrates how to use Microsoft Sentinel to detect successful RDP logins to a Windows VM hosted in Azure. It simulates a basic SOC alert pipeline: log ingestion, detection rule creation, and incident generation.

---

## Tools & Services
- Microsoft Azure (Free Tier)
- Windows 11 Pro Virtual Machine
- Microsoft Sentinel (SIEM)
- Log Analytics Workspace
- Data Connectors
- Kusto Query Language (KQL)

---

## Setup

### 1. Azure VM Creation
- Created a new Azure VM using a Windows 11 Pro image
- Enabled RDP and left default settings
- Screenshot: VM Overview Page

### 2. Sentinel Deployment
- Created a Log Analytics Workspace
- Deployed Microsoft Sentinel to the workspace
- Screenshot: Sentinel Overview Panel

### 3. Log Ingestion
- Added Windows Security Events via Data Connector
- Created Data Collection Rule to send logs from VM
- Screenshot: Data Connector Setup

### 4. Detection Logic
- Wrote custom KQL rule to detect successful logins from non-SYSTEM accounts:
```kql
SecurityEvent
| where EventID == 4624
| where Account != "SYSTEM"
| where LogonType == 10
