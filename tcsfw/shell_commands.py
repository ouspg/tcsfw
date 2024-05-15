"""Shell command 'ps'"""

from io import BytesIO, TextIOWrapper
from typing import Dict
from tcsfw.components import OperatingSystem
from tcsfw.event_interface import EventInterface, PropertyEvent
from tcsfw.model import IoTSystem, NetworkNode
from tcsfw.property import PropertyKey
from tcsfw.tools import NetworkNodeTool
from tcsfw.traffic import Evidence, EvidenceSource
from tcsfw.verdict import Verdict


class ShellCommandPs(NetworkNodeTool):
    """Shell command 'ps' tool adapter"""
    def __init__(self, system: IoTSystem):
        super().__init__("shell-ps", ".txt", system)

    def process_node(self, node: NetworkNode, data_file: BytesIO, interface: EventInterface, source: EvidenceSource):
        columns: Dict[str, int] = {}
        unexpected = {}
        os = OperatingSystem.get_os(node, add=self.load_baseline)
        with TextIOWrapper(data_file) as f:
            while True:
                line = f.readline().split()
                if not line:
                    break
                if not columns:
                    # header line
                    columns = {name[:2]: idx for idx, name in enumerate(line)}
                    continue
                if len(line) < len(columns):
                    continue  # bad line
                user = line[columns["US"]]
                cmd = line[columns["CM"]]
                if cmd.startswith("[") and cmd.endswith("]"):
                    continue  # kernel thread
                exp_ps = os.process_map.get(user) if os else None
                if self.load_baseline:
                    # learning the processes
                    cmd_0 = cmd.split()[0]
                    exp_ps = os.process_map.setdefault(user, [])
                    if cmd_0 not in exp_ps:
                        exp_ps.append(cmd_0)
                    continue
                if exp_ps is None:
                    self.logger.debug("User %s not in process map", user)
                    continue
                for ps in exp_ps:
                    if cmd.startswith(ps):
                        break
                else:
                    self.logger.debug("Command %s not expected process for %s", cmd, user)
                    unexpected.setdefault(user, []).append(cmd)
                    continue
                self.logger.debug("Command %s expected process for %s", cmd, user)

        if self.send_events:
            # send pass or fail verdicts
            evidence = Evidence(source)
            all_procs = set(os.process_map.keys())
            all_procs.update(unexpected.keys())
            for user in sorted(all_procs):
                key = PropertyKey("process", user)
                if user in unexpected:
                    ver = Verdict.FAIL
                    exp = f"Unexpected {user} processes: " + ", ".join(unexpected[user])
                else:
                    ver = Verdict.PASS
                    exp = ""
                ev = PropertyEvent(evidence, os, key.verdict(ver, explanation=exp))
                interface.property_update(ev)
