
# How to Create an Analytics Rule in Microsoft Sentinel

[![Azure](https://img.shields.io/badge/Microsoft%20Azure-0078D4?style=for-the-badge&logo=microsoft-azure&logoColor=white)](https://portal.azure.com/)  
[![KQL](https://img.shields.io/badge/KQL-0078D4?style=for-the-badge&logo=azure-data-explorer&logoColor=white)](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/)

This project demonstrates how to create a **Scheduled Analytics Rule** in Microsoft Sentinel to detect **potential brute-force attacks** on a monitored account (Adam). The rule uses **KQL queries** to identify repeated failed sign-in attempts and can automatically generate alerts and trigger automated responses.

---

## Prerequisites

- Access to the [Azure Portal](https://portal.azure.com/)  
- Microsoft Sentinel workspace configured  
- Permissions to create analytics rules and automation  

---

## Step 1: Login to Azure Portal 🔑

1. Open [https://portal.azure.com/](https://portal.azure.com/)  
2. Sign in with your Azure account credentials.

<details>
<summary>Screenshot: Azure Portal Login</summary>

![Azure Login Placeholder](path/to/screenshot.png)

</details>

---

## Step 2: Navigate to Analytics 📊

1. Go to **Configuration → Analytics**  
2. Click **Analytics** to open the Microsoft Sentinel analytics rules page  

<details>
<summary>Screenshot: Microsoft Sentinel Analytics Page</summary>

<img width="902" height="453" alt="analytics rules " src="https://github.com/user-attachments/assets/4f7169d6-6c0e-4aab-9f4e-f390a5a0c9fe" />


</details>

---

## Step 3: Create a New Scheduled Rule 🛠️

1. Click **Create** → launch **Analytics Rule Wizard**  
2. Select **Scheduled rule**  
3. Fill in the required fields:  
   - **Rule Name**: `Potential Brute-Force Attacks – Adam`  
   - **Description**: Detect repeated failed sign-ins  
   - **Severity**: Medium / High  

<details>
<summary>Screenshot: Analytics Rule Wizard – General Tab</summary>

![Wizard General Tab Placeholder](path/to/screenshot.png)

</details>

---

## Step 4: Set Rule Logic ⚡

Define the **core detection behavior**:

- Detection query (KQL)  
- Scheduling frequency  
- Alert threshold  
- Event grouping  
- Severity & MITRE ATT&CK mapping

**Example KQL Query for Brute-Force Detection:**

```kql
let lookback = 30d;
SigninLogs
| where TimeGenerated >= ago(30d)
| where ResultType != 0                                     // Failed sign-ins only
| where UserPrincipalName contains ""                       // Your domain
| summarize
      FailedAttempts = count(),
      FirstAttempt = min(TimeGenerated),
      LastAttempt = max(TimeGenerated),
      IPs = make_set(IPAddress, 5)
      by UserPrincipalName, IPAddress
| where FailedAttempts >= 5                                  // Threshold for brute-force
| order by FailedAttempts desc
