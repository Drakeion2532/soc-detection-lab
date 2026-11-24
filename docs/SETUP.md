# Setting up the lab (about 1–2 hours)

You need: a machine with **8 GB RAM free** for Wazuh (any OS that runs Docker), and the **Windows
machine you want to monitor** (your MSI works). They can be the same machine if it has enough RAM.

> Only run this on machines you own. The simulations are harmless and clean up after themselves,
> but they deliberately look like attacks.

## 1. Start Wazuh (the SIEM) in Docker

Follow the official single-node guide, which takes care of TLS certificates:
<https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html>

In short:

```bash
git clone https://github.com/wazuh/wazuh-docker.git -b v4.9.2   # use the current release tag
cd wazuh-docker/single-node
docker compose -f generate-indexer-certs.yml run --rm generator
docker compose up -d
```

Open `https://localhost` and sign in (default `admin` / `SecretPassword`; change it).

## 2. Install Sysmon on Windows

1. Download Sysmon from Microsoft Sysinternals: <https://learn.microsoft.com/sysinternals/downloads/sysmon>
2. Use a well-known community config, for example SwiftOnSecurity's:
   <https://github.com/SwiftOnSecurity/sysmon-config>
3. In an elevated prompt: `sysmon64.exe -accepteula -i sysmonconfig-export.xml`

## 3. Install the Wazuh agent on Windows and send it Sysmon logs

1. In the Wazuh dashboard: **Agents → Deploy new agent → Windows**, and run the command it gives you.
2. Add this to `C:\Program Files (x86)\ossec-agent\ossec.conf` inside `<ossec_config>`:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

3. Restart the agent: `Restart-Service -Name wazuh`

## 4. Load the lab's detection rules

Copy [`detections/wazuh/local_rules.xml`](../detections/wazuh/local_rules.xml) into the manager:

```bash
docker cp detections/wazuh/local_rules.xml single-node-wazuh.manager-1:/var/ossec/etc/rules/local_rules.xml
docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control restart
```

Check a rule before relying on it: `docker exec -it single-node-wazuh.manager-1 /var/ossec/bin/wazuh-logtest`,
then paste a Sysmon event (JSON) from the dashboard. If a group name differs in your Wazuh version
(for example `sysmon_event_13`), adjust `if_group` and note it in your incident report. That's real
detection-engineering work worth writing about.

## 5. Run the simulations

In an **elevated** PowerShell on the Windows machine:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\simulations\Invoke-LabSimulations.ps1              # all five techniques
.\simulations\Invoke-LabSimulations.ps1 -CleanupOnly # if a run was interrupted
```

It writes the time of each step to `simulations/simulation-log.csv`.

## 6. Investigate and write it up

In Wazuh, search `rule.id:[100101 TO 100106]` for the time range in the CSV. For each alert, copy
[`incidents/TEMPLATE.md`](../incidents/TEMPLATE.md) to `incidents/INC-2026-001.md` (and so on) and fill it
in from what you actually saw, with a screenshot. Commit each report as you finish it: a steady series of
your own commits is exactly what reviewers look for.

## Optional: Splunk

The same detections as Splunk searches are in [`detections/splunk/`](../detections/splunk), generated from
the Sigma rules with `python tools/build_splunk.py`. They assume Sysmon data with standard field names
(Splunk Add-on for Sysmon).
