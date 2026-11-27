"""Reversible connection blocking through Windows Defender Firewall (netsh advfirewall).

Safety rules:
  * never blocks critical Windows processes;
  * never blocks loopback/unspecified addresses;
  * every rule is named "NetSentinel Block <id>", recorded in the database and removable
    from Settings > Firewall rules or with: netsh advfirewall firewall delete rule name="<name>";
  * the GUI shows consequences and asks for explicit confirmation before calling block().
"""
from __future__ import annotations

import ipaddress
import logging
import os
import time
from dataclasses import dataclass

from utils import windows_api
from utils.helpers import exe_basename, short_id
from utils.permissions import is_admin

log = logging.getLogger(__name__)

PROTECTED = {"system", "svchost.exe", "lsass.exe", "services.exe", "wininit.exe", "csrss.exe",
             "winlogon.exe", "smss.exe", "msmpeng.exe", "mpdefendercoreservice.exe", "nissrv.exe",
             "securityhealthservice.exe", "explorer.exe", "dwm.exe", "spoolsv.exe",
             "searchindexer.exe", "taskhostw.exe", "registry", "fontdrvhost.exe", "dllhost.exe",
             "wuauclt.exe", "usocoreworker.exe", "trustedinstaller.exe", "tiworker.exe"}


@dataclass
class BlockPlan:
    exe: str
    remote_ip: str
    rule_name: str
    consequences: list[str]
    allowed: bool
    reason: str = ""


class FirewallManager:
    def __init__(self, db=None):
        self.db = db

    def plan(self, exe: str, remote_ip: str) -> BlockPlan:
        name = f"NetSentinel Block {short_id()[:8]}"
        base = exe_basename(exe)
        cons = [f"Outbound traffic from {base or 'this program'} to {remote_ip} will be dropped by Windows Firewall.",
                "Features of the program that rely on this destination may stop working.",
                "Other programs and other destinations are not affected.",
                f"The rule is reversible: remove '{name}' in Settings > Firewall rules."]
        if not windows_api.IS_WINDOWS:
            return BlockPlan(exe, remote_ip, name, cons, False, "Windows Firewall is only available on Windows")
        if not is_admin():
            return BlockPlan(exe, remote_ip, name, cons, False, "Administrator rights are required to create firewall rules")
        if not exe or not os.path.isabs(exe):
            return BlockPlan(exe, remote_ip, name, cons, False, "The executable path is unknown, so a program-scoped rule cannot be created")
        if base in PROTECTED:
            return BlockPlan(exe, remote_ip, name, cons, False, f"{base} is a critical Windows component and will not be blocked")
        try:
            ip = ipaddress.ip_address(remote_ip)
        except ValueError:
            return BlockPlan(exe, remote_ip, name, cons, False, "Invalid IP address")
        if ip.is_loopback or ip.is_unspecified:
            return BlockPlan(exe, remote_ip, name, cons, False, "Loopback/unspecified addresses are not blocked")
        if ip.is_private:
            cons.insert(1, "This is a LOCAL NETWORK address (router, printer, NAS…); blocking may break local features.")
        return BlockPlan(exe, remote_ip, name, cons, True)

    def block(self, plan: BlockPlan) -> tuple[bool, str]:
        if not plan.allowed:
            return False, plan.reason
        args = ["netsh", "advfirewall", "firewall", "add", "rule", f"name={plan.rule_name}", "dir=out",
                "action=block", f"remoteip={plan.remote_ip}", f"program={plan.exe}", "enable=yes",
                "profile=any", f"description=Created by NetSentinel on {time.ctime()} (reversible)"]
        r = windows_api.run_hidden(args, timeout=20)
        ok = r.returncode == 0
        msg = (r.stdout or r.stderr).strip()
        if ok and self.db:
            self.db.add_firewall_rule(plan.rule_name, plan.exe, plan.remote_ip, "out")
        log.info("Firewall block %s -> %s: %s", plan.exe, plan.remote_ip, "ok" if ok else msg)
        return ok, msg or "Rule created"

    def remove(self, rule_name: str) -> tuple[bool, str]:
        if not rule_name.startswith("NetSentinel Block "):
            return False, "Only rules created by NetSentinel can be removed here"
        if not is_admin():
            return False, "Administrator rights are required to remove firewall rules"
        r = windows_api.run_hidden(["netsh", "advfirewall", "firewall", "delete", "rule",
                                    f"name={rule_name}"], timeout=20)
        out = (r.stdout or r.stderr).strip()
        ok = r.returncode == 0 or "No rules match" in out
        if ok and self.db:
            self.db.remove_firewall_rule(rule_name)
        return ok, out or "Rule removed"

    def exists(self, rule_name: str) -> bool:
        r = windows_api.run_hidden(["netsh", "advfirewall", "firewall", "show", "rule", f"name={rule_name}"], timeout=20)
        return r.returncode == 0 and "No rules match" not in r.stdout
