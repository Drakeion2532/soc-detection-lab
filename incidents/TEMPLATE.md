# INC-YYYY-NNN: <short title, e.g. "Local account created from the command line">

Copy this file to `incidents/INC-YYYY-NNN.md` and fill it in **from what you actually saw** in Wazuh.
Paste real values; never fill in what you expected to see.

| | |
|---|---|
| **Date / time (UTC)** | from `simulations/simulation-log.csv` and the alert |
| **Host** | |
| **Alert** | Wazuh rule ID and description, level |
| **ATT&CK** | technique ID and name |
| **Severity (my call)** | low / medium / high, and why |
| **Verdict** | true positive (lab simulation) / false positive / benign |

## 1. Detection
What fired, when, and on which rule. Paste the key fields of the alert (image, command line,
parent process, user). Add a screenshot of the Wazuh event to `incidents/img/`.

## 2. Investigation
What else you looked at, and what it told you:
- parent and child processes (Sysmon Event ID 1)
- other alerts on the same host within ±15 minutes
- the user account and whether this is normal for them

## 3. Scope
Other hosts or users affected? How did you check?

## 4. Response
What you would do in a real SOC (contain, eradicate, recover), and what you actually did in the lab
(for example: the script removed the account; you confirmed with `Get-LocalUser`).

## 5. Detection quality
- Did the rule fire? How long after the activity?
- Any false positives during normal use of the machine?
- What would an attacker change to avoid this rule, and how would you catch that version?

## 6. Lessons learned
One or two concrete changes (a rule tweak, an allowlist, a new data source).
