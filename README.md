# SOC Detection Lab: Wazuh + Sysmon + Sigma

[![ci](https://github.com/Drakeion2532/soc-detection-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/Drakeion2532/soc-detection-lab/actions/workflows/ci.yml)

A home SOC lab for practising the full alert lifecycle on a real Windows endpoint:
**simulate an attack technique → detect it → investigate → write the incident report.**

```
 Windows endpoint (Sysmon + Wazuh agent)          Wazuh manager + dashboard (Docker)
 ┌──────────────────────────────────────┐        ┌──────────────────────────────────┐
 │ Invoke-LabSimulations.ps1            │  logs  │ local_rules.xml  (rules 1001xx)  │
 │  harmless ATT&CK technique simulations ├──────►│ alerts → investigation → report  │
 └──────────────────────────────────────┘        └──────────────────────────────────┘
                       same detections also as  Sigma  →  Splunk SPL
```

## Detections

| Technique | Simulation (harmless, auto-cleaned) | Sigma | Wazuh | Splunk |
|---|---|---|---|---|
| T1059.001 PowerShell | `powershell -enc` running `whoami` | [rule](detections/sigma/win_powershell_encoded_command.yml) | 100101 | [SPL](detections/splunk/win_powershell_encoded_command.spl) |
| T1053.005 Scheduled Task | `schtasks /create` (Notepad), then delete | [rule](detections/sigma/win_schtasks_create.yml) | 100102 | [SPL](detections/splunk/win_schtasks_create.spl) |
| T1136.001 Local Account | `net user /add` (disabled), then delete | [rule](detections/sigma/win_local_account_created.yml) | 100103 | [SPL](detections/splunk/win_local_account_created.spl) |
| T1547.001 Run Key | Run value → Notepad, then remove | [rule](detections/sigma/win_registry_run_key.yml) | 100104 | [SPL](detections/splunk/win_registry_run_key.spl) |
| T1033 / T1082 Discovery | `whoami`, `hostname`, `systeminfo`, `ipconfig` burst | [rule + correlation](detections/sigma/win_discovery_burst.yml) | 100105–100106 | [SPL](detections/splunk/win_discovery_burst.spl) |

Every rule lists its false positives and a level. The discovery rule uses a Sigma **correlation**
(3+ distinct tools from one parent within 5 minutes), not the deprecated pipe syntax.

## What's tested (CI)

- Every Sigma rule parses with pySigma and carries an ATT&CK tag; IDs are unique.
- Every technique the simulation script can run has **both** a Sigma rule and a Wazuh rule.
- The Wazuh patterns fire on the events the simulation produces and stay quiet on ordinary ones.
- The Splunk queries are regenerated from Sigma, so the three formats never drift apart.
- The PowerShell script is parsed and linted with PSScriptAnalyzer.

## Run it

Setup takes about 1–2 hours: [docs/SETUP.md](docs/SETUP.md).

```powershell
# elevated PowerShell on the Windows endpoint
.\simulations\Invoke-LabSimulations.ps1
```

```bash
pip install -r requirements.txt
pytest -q                          # rule consistency + detection logic
python tools/build_splunk.py       # regenerate Splunk SPL from Sigma
```

## Incident reports

[`incidents/`](incidents) holds one report per investigated alert, written from what the lab actually
showed, using [the template](incidents/TEMPLATE.md): detection, investigation, scope, response, detection
quality and lessons learned.

## Roadmap

- Credential-access simulations (LSASS access) once Defender exclusions are set up safely
- A Linux endpoint (auditd) with SSH brute-force and sudo-abuse detections
- Map every alert to a short response playbook

## How this was built

I designed the lab, the detections and their tests, and used AI pair-programming (Claude Code) for
implementation. The incident reports are written from my own lab runs.

## Licence

MIT © 2026 [Shubhan Punde](https://github.com/Drakeion2532). See [LICENSE](LICENSE).
