# Troubleshooting Notes

## Lab 50 – Dormant Account Activity Investigation

## Issue 1 – Logon Auditing Was Disabled

### Problem

The following audit-policy checks returned `No Auditing`:

```cmd
auditpol /get /subcategory:"Logon"
```

```cmd
auditpol /get /subcategory:"Account Lockout"
```

```cmd
auditpol /get /subcategory:"Other Logon/Logoff Events"
```

### Impact

The endpoint may not provide complete authentication telemetry for the controlled account.

### Resolution

Document the audit configuration as an evidence limitation.

Do not conclude that a logon did not happen solely because a corresponding event is missing.

---

## Issue 2 – Event ID 4624 Was Present but Belonged to the Wrong Account

### Problem

A 4624 event was found, but the event showed:

`Account Name: DESKTOP-9MMM37V$`

and:

`Security ID: SYSTEM`

### Impact

This event represents machine/system authentication and cannot be used as evidence that `DormantUser` logged on.

### Resolution

Always inspect:

- Account Name
- Account Domain
- Logon ID
- Logon Type
- Subject account

before attributing a 4624 event to a specific user.

---

## Issue 3 – Wazuh Event Was Unrelated

### Problem

The Wazuh Discover evidence showed:

`Event ID: 16384`

from:

`Software Protection Platform Service`

### Impact

The event was unrelated to dormant-account authentication.

### Resolution

Exclude unrelated telemetry from the authentication assessment.

The presence of an event in Wazuh does not automatically make it relevant to the current investigation.

---

## Issue 4 – DormantUser Baseline Showed Last Logon Never

### Observation

`net user DormantUser` displayed:

`Last logon: Never`

The PowerShell baseline also did not establish a prior user logon.

### Interpretation

This supports the intended dormant-account baseline.

### Resolution

Retain the baseline as evidence and use it as the starting point for future authentication comparisons.

---

## Issue 5 – LastLogon Information Can Be Misleading

### Problem

Different Windows account-reporting mechanisms may show different values or timestamps.

### Resolution

Do not rely on a single field for proving account activity.

Correlate:

- `net user`
- `Get-LocalUser`
- Event ID 4624
- Event ID 4625
- Event ID 4634
- Event ID 4647
- Wazuh telemetry

---

## Issue 6 – Large Number of 4624 Events

### Problem

The Windows Security log contained many successful logon events.

### Cause

Windows systems generate authentication events for users, services, scheduled operations, and machine accounts.

### Resolution

Filter the investigation by:

- Account Name
- Logon ID
- Logon Type
- Timestamp
- Workstation
- Source address

Do not assume every 4624 represents an interactive human-user login.

---

## Issue 7 – No DormantUser Authentication Evidence

### Problem

No captured event definitively showed `DormantUser` authentication.

### Cause

The intended authentication event was either not generated, not audited, not collected, or not captured in the screenshots.

### Resolution

Record the result as an evidence gap.

Do not fabricate a 4624 or classify the account as compromised without supporting evidence.

---

# Lessons Learned

- Authentication investigations depend heavily on correct audit configuration.
- Event ID 4624 must be attributed to the exact account shown in the event.
- Machine accounts and user accounts must be distinguished.
- Wazuh events must be validated for relevance.
- Missing telemetry is an investigation limitation, not proof that an action never occurred.
- A strong DFIR report clearly separates confirmed observations from assumptions.
