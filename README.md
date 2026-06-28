# Deloitte Cyber Job Simulation — Web Log Analysis

**Platform:** Forage  
**Issued:** June 28, 2026  
**Certificate:** [Deloitte Cyber Job Simulation — Certificate of Completion](./deloitte_completion_certificate.pdf)

---

## Overview

This task was part of Deloitte's Cybersecurity Job Simulation on Forage. A news publication leaked sensitive operational data belonging to **Daikibo Industrials**, a Deloitte client. The suspected source was a breach of their internal factory status dashboard (telemetry board). My job was to analyse web request logs to determine:

1. Whether the breach could have been carried out by an external attacker (i.e., someone with no access to Daikibo's VPN/intranet)
2. Whether any suspicious automated activity could be identified in the logs, and if so — who the user was

---

## Log File Structure

The file `web_activity.log` contains blocks of HTTP request records, one block per unique IP address. Each block includes:

- The device's static internal IP address
- A table of requests sorted by time, showing: timestamp, HTTP method, endpoint, optional `authorizedUserId`, and HTTP status code

Normal user behaviour follows this pattern:

```
GET "/"                          → 401 (session check, no auth yet)
GET "/login"                     → 200
GET "/login.css"                 → 200
GET "/login.js"                  → 200
POST "/login"                    → 200 (credentials submitted)
GET "/" {authorizedUserId: ...}  → 200 (authenticated dashboard)
GET "/index.css" + "/index.js"   → 200 (page assets load)
GET "/api/factory/status?..."    → 200 (user browses data manually)
```

---

## Task 1 — Could an External Attacker Have Done This?

**Finding: No.**

All IP addresses in the log file are in the `192.168.0.x` range — private RFC 1918 addresses that are only reachable from within Daikibo's internal network. There is no public-facing IP in any block.

This means the breach **required access to Daikibo's intranet or VPN**. An attacker on the open internet could not have directly accessed the telemetry dashboard. The breach was either:
- An insider threat, or
- An external attacker who had already gained VPN/intranet access through a separate initial compromise

---

## Task 2 — Identifying Suspicious Activity

### What I looked for

The task hint noted there is **no auto-refresh or push mechanism** in the dashboard — users must manually refresh to see updated data. So if any IP was polling the API at a perfectly regular interval, that would indicate a script, not a human.

### The anomaly: IP `192.168.0.101`

This block stood out immediately — with **~130+ API requests** it was far larger than any other block (most users had 10–20 requests).

Examining the timestamps after the initial normal login on June 25:

```
2021-06-25T17:00:48Z  GET /api/factory/machine/status?factory=meiyo&machine=*
2021-06-25T17:00:48Z  GET /api/factory/machine/status?factory=seiko&machine=*
2021-06-25T17:00:48Z  GET /api/factory/machine/status?factory=shenzhen&machine=*
2021-06-25T17:00:48Z  GET /api/factory/machine/status?factory=berlin&machine=*

2021-06-25T18:00:48Z  GET /api/factory/machine/status?factory=meiyo&machine=*
2021-06-25T18:00:48Z  GET /api/factory/machine/status?factory=seiko&machine=*
...
```

**Every hour, on the exact second `:00:48`, all 4 factories were queried simultaneously.** This pattern repeated continuously across June 25–26 — behaviour that is impossible to produce manually and is a clear indicator of an automated script (e.g., a cron job or scheduled task).

### Session expiry — the script doesn't notice

At midnight on June 26, the user's session expired. A human would notice the dashboard breaking and log back in. The script didn't:

```
2021-06-26T00:00:48Z  GET /api/factory/machine/status?factory=meiyo&machine=*   → 401 (UNAUTHORIZED)
2021-06-26T01:00:48Z  GET /api/factory/machine/status?factory=meiyo&machine=*   → 401 (UNAUTHORIZED)
...continuing to return 401 for every subsequent hour...
```

The script blindly kept polling for ~16 hours through 401 responses, which is a strong behavioural IOC (Indicator of Compromise).

Eventually, a **manual re-login occurred at 16:04 on June 26**, after which the automated polling resumed with 200 (SUCCESS) responses.

### Attacker's User ID

```
mdB7yD2dp1BFZPontHBQ1Z
```

This ID appears in every authenticated request from `192.168.0.101`.

---

## Summary of Findings

| Finding | Detail |
|---|---|
| External attacker possible? | **No** — all IPs are internal (192.168.0.x) |
| Suspicious IP | `192.168.0.101` |
| Suspicious user ID | `mdB7yD2dp1BFZPontHBQ1Z` |
| Attack type | Automated script polling all factory statuses every 1 hour exactly |
| IOC | Continued polling through 401 errors for 16+ hours; re-login then resumed scripted access |
| Data exposed | Machine statuses across all 4 factories: meiyo, seiko, shenzhen, berlin |

---

## Skills Demonstrated

- Web server log analysis
- Identifying automated vs. human browsing behaviour
- Recognising IOCs in access patterns (interval-based polling, blind 401 continuation)
- Understanding HTTP authentication flows and session management
- Communicating security findings clearly
