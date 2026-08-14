# Investigation Timeline


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

