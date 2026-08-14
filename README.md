# Windows Dormant Account Activity Investigation with Wazuh (DFIR Lab 50)

## Overview

Dormant accounts can become important investigation leads when they suddenly show authentication activity after a long period of inactivity. However, a dormant-account investigation requires more than finding a successful logon event. The analyst must first establish the account's baseline state, verify whether authentication auditing is available, identify the actual account associated with any logon event, and correlate the activity with Wazuh.

In this lab, a controlled local account named `DormantUser` was created and its baseline state was examined. Windows auditing configuration was also reviewed before investigating Security Event ID 4624 and Wazuh endpoint telemetry.

The investigation additionally demonstrated an important DFIR principle: an available 4624 event is not sufficient unless it can be correctly attributed to the account under investigation.

---

# Lab Objectives

- Establish a baseline for a dormant Windows account.
- Determine whether the account has previous logon history.
- Verify the state of Windows logon auditing.
- Investigate Security Event ID 4624.
- Distinguish a user logon from a machine-account or system logon.
- Review the availability of related authentication events.
- Correlate endpoint activity with Wazuh Discover.
- Identify evidence gaps that prevent a definitive conclusion.
- Document the difference between observed evidence and assumed activity.

---

# Lab Environment

| Component          | Value                                      |
| ------------------ | ------------------------------------------ |
| Host OS            | Windows 11 Pro                             |
| SIEM               | Wazuh 4.12                                 |
| Endpoint Agent     | Wazuh Agent                                |
| Endpoint Name      | DESKTOP-9MMM37V                            |
| Agent ID            | 001                                        |
| Test Account       | DormantUser                                |
| Investigation Type | Dormant Account Activity Investigation    |
| Primary Events     | 4624 / 4625 / 4634 / 4647                 |
| Investigation UI   | Wazuh Discover                             |
| Tools Used         | PowerShell, CMD, Event Viewer, Wazuh      |

---

# Tools Used

- PowerShell
- Command Prompt
- Windows Event Viewer
- `Get-LocalUser`
- `net user`
- `auditpol`
- Wazuh Manager
- Wazuh Discover
- Wazuh Agent

---

# Investigation Scenario

A Windows endpoint is being reviewed for possible use of an account that normally shows little or no activity. The SOC analyst creates a controlled test account and establishes its baseline before reviewing authentication telemetry.

The investigation must determine whether the account has a previous logon history, whether Windows is configured to audit authentication activity, and whether any available 4624 events can actually be attributed to the account being investigated.

---

# Investigation Workflow

```text
Verify Wazuh Agent
        ↓
Create Test Account
        ↓
Establish Dormancy Baseline
        ↓
Check Authentication Auditing
        ↓
Review Security Log
        ↓
Validate Event 4624 Account Identity
        ↓
Search Wazuh Discover
        ↓
Identify Evidence Gaps
        ↓
Construct Timeline
        ↓
Final Assessment
```

---

# Investigation Steps

### Step 1 – Verify Wazuh Agent

On the Wazuh server:

```bash
sudo /var/ossec/bin/agent_control -i 001
```

Observed:

- Agent ID: `001`
- Agent Name: `DESKTOP-9MMM37V`
- Status: `Active`
- Operating System: Windows 11 Pro

---

### Step 2 – Create a Controlled Test Account

Command Used:

```cmd
net user DormantUser Password123! /add
```

The account creation completed successfully.

The account was then reviewed using:

```cmd
net user DormantUser
```

Observed:

- Account active: Yes
- Account expires: Never
- Password required: Yes
- Local group membership: `Users`
- Last logon: `Never`

---

### Step 3 – Establish the Dormancy Baseline

PowerShell command:

```powershell
Get-LocalUser -Name "DormantUser" |
Select-Object Name, Enabled, LastLogon, PasswordExpires
```

Observed:

- Name: `DormantUser`
- Enabled: `True`
- LastLogon: No established prior user logon in the displayed baseline
- PasswordExpires: Displayed by the endpoint

This provided the initial dormant-account baseline.

---

### Step 4 – Check Authentication Auditing

Commands used:

```cmd
auditpol /get /subcategory:"Logon"
```

```cmd
auditpol /get /subcategory:"Account Lockout"
```

```cmd
auditpol /get /subcategory:"Other Logon/Logoff Events"
```

Observed:

`No Auditing`

for the displayed categories.

This is an important investigation limitation because the endpoint was not configured to provide full authentication auditing through these audit subcategories.

---

### Step 5 – Review Windows Security Events

PowerShell query:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    Id=4624,4625,4634,4647
} -MaxEvents 500
```

The available Security log contained multiple 4624 events.

However, the displayed 4624 event identified:

- Security ID: `SYSTEM`
- Account Name: `DESKTOP-9MMM37V$`
- Account Domain: `WORKGROUP`

This is a machine-account logon event, not evidence of a `DormantUser` logon.

---

### Step 6 – Review Event ID 4624

Event ID 4624 was examined in Event Viewer.

Observed:

`An account was successfully logged on.`

The captured event showed the endpoint's machine account:

`DESKTOP-9MMM37V$`

Therefore, this event cannot be used to conclude that `DormantUser` authenticated.

---

### Step 7 – Investigate Wazuh Discover

Wazuh Discover was reviewed for:

```text
agent.name: DESKTOP-9MMM37V
```

The captured Wazuh evidence showed an Application log event from:

`Software Protection Platform Service`

with:

`Event ID: 16384`

This event is unrelated to the DormantUser authentication investigation and was not used as proof of account activity.

---

# Key Findings

- Wazuh Agent `001` was active and reporting.
- `DormantUser` was successfully created as a controlled test account.
- The account was enabled and belonged to the standard `Users` group.
- `net user DormantUser` initially reported `Last logon: Never`.
- The PowerShell baseline did not establish a prior user logon for the test account.
- Windows logon auditing was shown as `No Auditing` for the checked audit subcategories.
- Security Event ID 4624 was available in the endpoint.
- The captured 4624 event belonged to the machine account `DESKTOP-9MMM37V$`.
- The captured 4624 event does not prove a `DormantUser` logon.
- The captured Wazuh event was unrelated to the authentication investigation.
- A definitive DormantUser authentication event was therefore not established from the screenshots collected.

---

# Evidence Correlation

| Evidence | Source | Observation | DFIR Value |
|---|---|---|---|
| Wazuh Agent | Wazuh Manager | Agent `001` Active | Confirms endpoint visibility |
| Test Account | `net user` | `DormantUser` created | Establishes controlled account |
| Account Baseline | `Get-LocalUser` | Account enabled; baseline recorded | Establishes dormancy context |
| Account History | `net user` | Last logon initially `Never` | Supports dormant baseline |
| Audit Policy | `auditpol` | No Auditing | Identifies authentication telemetry limitation |
| Security Event | Event Viewer | 4624 available | Confirms authentication telemetry exists |
| 4624 Account | Event Viewer | `DESKTOP-9MMM37V$` / SYSTEM | Machine-account event, not DormantUser |
| Wazuh Event | Wazuh Discover | Event ID 16384 / Software Protection | Unrelated supporting telemetry |
| Evidence Gap | Analyst | No confirmed DormantUser 4624 | Prevents definitive authentication conclusion |

---

# DFIR Value

Dormant-account investigations require careful attribution.

A successful 4624 event does not automatically mean that the account under investigation logged in. The analyst must validate:

- Account name
- Domain
- Logon type
- Logon ID
- Source information
- Timestamp
- Session context

The lab also demonstrates the importance of checking audit policy before drawing conclusions from missing authentication events.

---

# Skills Practiced

- Dormant Account Analysis
- Windows Account Baseline
- Authentication Investigation
- Event ID 4624 Analysis
- Event ID 4625 Analysis
- Logoff Event Analysis
- Windows Audit Policy Analysis
- Wazuh Discover
- Evidence Attribution
- Evidence Gap Identification
- DFIR Timeline Construction
- SOC Investigation

---

# MITRE ATT&CK Context

Dormant-account investigations may provide context for several authentication-related techniques.

Relevant ATT&CK areas include:

- `T1078 – Valid Accounts`
- `T1078.001 – Valid Accounts: Default Accounts`
- `T1078.002 – Valid Accounts: Domain Accounts`

The specific technique should only be mapped when the evidence supports unauthorized use of a valid account.

---

# Evidence Limitation

The captured evidence does not establish that `DormantUser` successfully logged on.

The available 4624 screenshot shows the machine account:

`DESKTOP-9MMM37V$`

rather than:

`DormantUser`

In addition, the checked authentication audit policies reported `No Auditing`.

Therefore, the correct DFIR conclusion is that the **dormant-account baseline was established, but unauthorized or unexpected DormantUser authentication was not conclusively demonstrated in the captured evidence**.

---

# Outcome

Successfully established a controlled dormant-account baseline, verified Wazuh endpoint visibility, reviewed Windows authentication auditing, examined Security Event ID 4624, and identified an important evidence-attribution limitation.

The investigation demonstrated why SOC analysts must validate the exact account represented by a security event and distinguish between confirmed evidence, unrelated telemetry, and missing evidence.
