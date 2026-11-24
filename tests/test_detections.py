"""Keep the lab consistent: every simulated technique has a Sigma rule and a Wazuh rule, the Splunk
queries are regenerated from Sigma, and the Wazuh patterns fire on the simulation's events and not on
ordinary ones."""
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
SIGMA = ROOT / "detections" / "sigma"
WAZUH = ROOT / "detections" / "wazuh" / "local_rules.xml"
SIM = ROOT / "simulations" / "Invoke-LabSimulations.ps1"


def sigma_docs():
    for f in sorted(SIGMA.glob("*.yml")):
        for doc in yaml.safe_load_all(f.read_text()):
            yield f.name, doc


def simulated_techniques():
    m = re.search(r"ValidateSet\(([^)]*)\)", SIM.read_text())
    return {t.strip(" '") for t in m.group(1).split(",")} - {"All"}


def wazuh_rules():
    text = WAZUH.read_text().split("-->", 1)[1]
    return ET.fromstring(f"<root>{text}</root>").iter("rule")


def test_sigma_rules_are_complete_and_unique():
    from sigma.collection import SigmaCollection
    ids = []
    for f in sorted(SIGMA.glob("*.yml")):
        assert not SigmaCollection.from_yaml(f.read_text()).errors, f.name
    for name, d in sigma_docs():
        for key in ("title", "id", "status", "description", "level", "tags", "author", "date"):
            assert key in d, f"{name} missing {key}"
        assert "detection" in d or "correlation" in d, name
        assert any(re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", t) for t in d["tags"]), name
        ids.append(d["id"])
    assert len(ids) == len(set(ids))


def test_every_simulated_technique_is_detected_by_sigma_and_wazuh():
    sigma_tags = {t.split(".", 1)[1].upper() for _, d in sigma_docs() for t in d["tags"] if t.startswith("attack.t")}
    wazuh_ids = {i.text for r in wazuh_rules() for i in r.iter("id")}
    for tech in simulated_techniques():
        assert tech in sigma_tags, f"no Sigma rule for {tech}"
        assert tech in wazuh_ids, f"no Wazuh rule for {tech}"


def test_wazuh_rule_ids_are_in_the_lab_range_and_unique():
    ids = [int(r.get("id")) for r in wazuh_rules()]
    assert len(ids) == len(set(ids)) and all(100100 <= i <= 100199 for i in ids)
    assert all(r.find("mitre") is not None for r in wazuh_rules())


def test_splunk_queries_are_up_to_date():
    from build_splunk import build
    for name, spl in build().items():
        path = ROOT / "detections" / "splunk" / f"{name}.spl"
        assert path.exists() and path.read_text() == spl, f"run python tools/build_splunk.py ({name})"


def pattern(rule_id, field):
    for r in wazuh_rules():
        if r.get("id") == rule_id:
            for f in r.iter("field"):
                if f.get("name") == field:
                    return re.compile(f.text.replace("(?i)", ""), re.I)
    raise KeyError((rule_id, field))


# (rule, image, command line or registry key, should fire?)
CASES = [
    ("100101", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "powershell.exe -NoProfile -enc dwBoAG8AYQBtAGkA", True),
    ("100101", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "powershell.exe -NoProfile -File backup.ps1", False),
    ("100102", r"C:\Windows\System32\schtasks.exe", 'schtasks.exe /Create /TN SOCLabTask /TR notepad.exe /SC DAILY', True),
    ("100102", r"C:\Windows\System32\schtasks.exe", "schtasks.exe /Query", False),
    ("100103", r"C:\Windows\System32\net.exe", "net.exe user SOCLabUser Xy12!a1 /add /active:no", True),
    ("100103", r"C:\Windows\System32\net.exe", "net.exe user SOCLabUser /delete", False),
    ("100105", r"C:\Windows\System32\whoami.exe", "whoami /all", True),
    ("100105", r"C:\Windows\System32\notepad.exe", "notepad.exe", False),
]


@pytest.mark.parametrize("rule,image,cmd,fires", CASES)
def test_wazuh_patterns_on_sample_events(rule, image, cmd, fires):
    img_ok = bool(pattern(rule, "win.eventdata.image").search(image))
    try:
        cmd_ok = bool(pattern(rule, "win.eventdata.commandLine").search(cmd))
    except KeyError:
        cmd_ok = True                       # rule matches on image only
    assert (img_ok and cmd_ok) is fires


def test_run_key_pattern():
    p = pattern("100104", "win.eventdata.targetObject")
    assert p.search(r"HKU\S-1-5-21-1\Software\Microsoft\Windows\CurrentVersion\Run\SOCLabRun")
    assert not p.search(r"HKU\S-1-5-21-1\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders")
