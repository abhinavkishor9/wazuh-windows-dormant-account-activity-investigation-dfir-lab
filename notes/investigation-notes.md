# Investigation Notes

## Lab Summary

This investigation examined a controlled Windows account that was intended to represent a dormant user and evaluated whether available endpoint telemetry could establish subsequent authentication activity.

The analysis combined local account information, Windows audit-policy configuration, Security Event ID 4624, and Wazuh Discover. The most important result was the identification of an evidence limitation: the captured 4624 event represented the machine account rather than the controlled `DormantUser` account.

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

An analyst wants to determine whether an account with little or no known activity has recently become active on a Windows endpoint.

The investigation establishes the account's baseline first and then evaluates authentication telemetry to determine whether the account can be linked to a successful or failed logon.

The key investigative requirement is accurate attribution. A successful authentication event involving a machine account or SYSTEM context cannot be treated as evidence that the dormant user account authenticated.

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

## DFIR Analysis

The account baseline was successfully established, but the available authentication evidence did not demonstrate that `DormantUser` performed a logon.

The captured 4624 event involved `DESKTOP-9MMM37V$`, which is the machine account associated with the Windows endpoint. Treating that event as a DormantUser login would create an attribution error.

The `auditpol` results further explain why authentication evidence may be incomplete. The checked logon-related audit subcategories reported `No Auditing`.

The Wazuh Discover screenshot also did not provide relevant evidence of DormantUser authentication. Instead, it showed an unrelated Software Protection Platform event.

---

## Analyst Observations

- A dormant-account baseline should be established before investigating suspicious activity.
- `net user` and `Get-LocalUser` provide useful account-state information.
- Authentication audit policy should be checked before interpreting missing events.
- Event ID 4624 must be attributed to the exact account shown in the event.
- Machine-account activity should not be confused with human-user authentication.
- Wazuh visibility does not guarantee that every required authentication event is available.
- Unrelated Wazuh events should not be used to support an authentication conclusion.
- Evidence gaps must be documented rather than filled with assumptions.

---

## Investigation Assessment

The evidence supports:

- Creation of the controlled `DormantUser` account.
- Establishment of a baseline showing no prior logon.
- Active Wazuh endpoint communication.
- Availability of Security Event ID 4624.
- Presence of a machine-account 4624 event.

The evidence does not support:

- A confirmed `DormantUser` successful logon.
- A confirmed `DormantUser` failed logon.
- A confirmed suspicious authentication event.

Therefore, the correct assessment is:

**Dormant account baseline established, but account activation not conclusively demonstrated from the captured evidence.**

---

## Conclusion

The investigation demonstrated the importance of account attribution and telemetry validation during dormant-account investigations. Although 4624 events were available, the captured event represented the Windows machine account rather than the controlled dormant user, while authentication auditing was not fully enabled.

The investigation therefore concluded with an explicit evidence limitation instead of incorrectly attributing unrelated authentication activity to `DormantUser`.
