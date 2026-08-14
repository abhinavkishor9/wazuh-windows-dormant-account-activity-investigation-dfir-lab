# Investigation Timeline

## Lab 50 – Dormant Account Activity Investigation

| Time / Sequence | Activity | Evidence | Significance |
|---|---|---|---|
| 1 | Verified Wazuh agent | Wazuh Manager | Endpoint reporting confirmed |
| 2 | Created `DormantUser` | Command Prompt | Controlled test account established |
| 3 | Reviewed account properties | `net user` | Last logon initially showed `Never` |
| 4 | Reviewed LocalUser baseline | PowerShell | Account state documented |
| 5 | Checked authentication auditing | `auditpol` | Logon-related auditing reported `No Auditing` |
| 6 | Searched Security log | PowerShell | Authentication events located |
| 7 | Reviewed 4624 event | Event Viewer | Event attributed to `DESKTOP-9MMM37V$` |
| 8 | Reviewed Wazuh endpoint | Wazuh Discover | Endpoint telemetry available |
| 9 | Reviewed Wazuh event | Wazuh Discover | Event 16384 from Software Protection Platform |
| 10 | Correlated evidence | Analyst | 4624 not attributed to `DormantUser` |
| 11 | Identified evidence gap | Analyst | DormantUser authentication not confirmed |
| 12 | Completed assessment | Analyst | Investigation documented |

---

# Investigation Flow

```text
Verify Wazuh Agent
        ↓
Create DormantUser
        ↓
Establish Account Baseline
        ↓
Check Last Logon
        ↓
Check Authentication Auditing
        ↓
Review Security Events
        ↓
Validate 4624 Account Identity
        ↓
Review Wazuh Telemetry
        ↓
Exclude Unrelated Events
        ↓
Identify Evidence Gap
        ↓
Final Assessment
```

---

# Account Baseline Timeline

| Evidence Point | Observation |
|---|---|
| Account Name | `DormantUser` |
| Account Status | Enabled |
| Account Group | `Users` |
| Account Creation | `14-08-2026` |
| Initial Last Logon | `Never` |
| Authentication Audit | `No Auditing` for checked subcategories |

---

# Authentication Evidence Timeline

The Security log contained multiple 4624 events.

The captured 4624 event showed:

```text
Security ID  : SYSTEM
Account Name : DESKTOP-9MMM37V$
Domain       : WORKGROUP
```

This confirms a successful authentication-related event, but it does not establish a successful logon by `DormantUser`.

---

# Wazuh Evidence Timeline

The Wazuh endpoint was confirmed as:

```text
Agent ID   : 001
Agent Name : DESKTOP-9MMM37V
Status     : Active
```

The captured Wazuh Discover event showed:

```text
Channel    : Application
Event ID   : 16384
Source     : Software Protection Platform Service
```

This event was unrelated to the DormantUser authentication investigation and was therefore excluded from the final authentication assessment.

---

# Evidence Correlation

```text
DormantUser Created
        ↓
Last Logon = Never
        ↓
Authentication Auditing = No Auditing
        ↓
4624 Events Found
        ↓
Captured 4624 = DESKTOP-9MMM37V$
        ↓
Machine Account ≠ DormantUser
        ↓
Wazuh Telemetry Reviewed
        ↓
No Confirmed DormantUser Authentication
```

---

# Timeline Assessment

The investigation successfully established the baseline state of the controlled dormant account and confirmed that the endpoint was reporting to Wazuh.

However, the available authentication evidence did not demonstrate that `DormantUser` successfully authenticated. The captured 4624 event represented the Windows machine account, and the checked logon audit policies were not enabled.

Therefore, the timeline supports a **dormant-account baseline investigation**, but not a confirmed dormant-account compromise.

---

# Final Analyst Assessment

The correct investigative conclusion is:

**No confirmed `DormantUser` authentication was established from the captured evidence.**

The primary findings were:

- Dormant account baseline established.
- Wazuh agent active.
- Authentication auditing limitation identified.
- 4624 event observed.
- 4624 event attributed to machine account.
- Wazuh event reviewed and found unrelated.
- DormantUser activity remains unconfirmed.
