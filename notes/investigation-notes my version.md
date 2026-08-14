# Investigation Notes

## Lab Summary

This investigation examined a controlled Windows account that was intended to represent a dormant user and evaluated whether available endpoint telemetry could establish subsequent authentication activity.

---

## Analyst Methodology

1. Verify Wazuh endpoint connectivity.
2. Create the controlled test account.
3. Examine its account state and previous logon information.
4. Review Windows authentication auditing configuration.
5. Search the Security log for authentication events.
6. Validate the exact account represented by 4624.
7. Review available Wazuh telemetry.
8. Separate relevant evidence from unrelated events.
9. Identify gaps that prevent attribution.
10. Document the final assessment.

---

## Investigation Scenario


A local Windows account has been identified as inactive and is being reviewed for unexpected authentication activity. The SOC analyst must determine whether the account has actually been used recently or whether available authentication events belong to another system identity.

The investigation focuses on:

Account activity baseline
Successful and failed logons
Logon type
Account and domain identity
Logon/session identifiers
Wazuh authentication telemetry
Evidence gaps caused by audit configuration

The objective is to determine whether there is sufficient evidence to support dormant-account activation, without attributing unrelated system or machine-account events to the user.


---

## Evidence Collected

### Evidence 1 – Wazuh Agent Status

Command Used:

```bash
sudo /var/ossec/bin/agent_control -i 001
```

Finding:

The Wazuh agent was active and associated with `DESKTOP-9MMM37V`.

---

### Evidence 2 – Controlled Account Creation

Command Used:

```cmd
net user DormantUser Password123! /add
```

Finding:

The test account was created successfully.

---

### Evidence 3 – Account Properties

Command Used:

```cmd
net user DormantUser
```

Observed:

- Account active: Yes
- Account expires: Never
- Password required: Yes
- Local group: `Users`
- Last logon: `Never`

Finding:

The account had no prior logon recorded at the time of the baseline.

---

### Evidence 4 – PowerShell Account Baseline

Command Used:

```powershell
Get-LocalUser -Name "DormantUser" |
Select-Object Name, Enabled, LastLogon, PasswordExpires
```

Finding:

Established the current account state and provided a second source for the account baseline.

---

### Evidence 5 – Authentication Audit Configuration

Commands Used:

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

Finding:

The endpoint did not have the checked authentication audit subcategories enabled, creating a significant evidence limitation.

---

### Evidence 6 – Security Event 4624

PowerShell query:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    Id=4624,4625,4634,4647
} -MaxEvents 500
```

Finding:

Multiple 4624 events were available in the Security log.

However, the captured Event Viewer evidence showed:

- Security ID: `SYSTEM`
- Account Name: `DESKTOP-9MMM37V$`
- Account Domain: `WORKGROUP`

This is a machine-account authentication event.

---

### Evidence 7 – Wazuh Discover

Search:

```text
agent.name: DESKTOP-9MMM37V
```

Finding:

Wazuh provided endpoint telemetry, but the captured Wazuh evidence displayed an unrelated Software Protection Platform event:

- Channel: `Application`
- Event ID: `16384`
- Source: `Software Protection Platform Service`

This event was excluded from the authentication assessment.

---

## Evidence Correlation

| Evidence | Relevant? | Interpretation |
|---|---|---|
| `DormantUser` account creation | Yes | Establishes controlled account |
| `Last logon: Never` | Yes | Supports dormant baseline |
| `auditpol` output | Yes | Shows authentication audit limitation |
| Security Event 4624 | Yes | Authentication event exists |
| 4624 account `DESKTOP-9MMM37V$` | Yes | Machine account, not DormantUser |
| Wazuh Agent status | Yes | Confirms endpoint visibility |
| Wazuh Event 16384 | No | Unrelated Software Protection event |
| DormantUser 4624 | Not established | Missing required evidence |

---

