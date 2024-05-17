"""Shell command 'ps'"""

from io import BytesIO, TextIOWrapper
import re
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

        # expected processes as regexps
        regexp_map = {}
        for user, ps_list in os.process_map.items():
            regexp_map[user] = [re.compile(ps) for ps in ps_list]

        with TextIOWrapper(data_file) as f:
            while True:
                line = f.readline().split(maxsplit=len(columns) -1 if columns else -1)
                if not line:
                    break
                if not columns:
                    # header line, use first two characters (headers are truncated for narrow data)
                    columns = {name[:2]: idx for idx, name in enumerate(line)}
                    continue
                if len(line) < len(columns):
                    continue  # bad line
                user = line[columns["US"]].strip()
                cmd = line[columns["CM"]].strip()
                if cmd.startswith("[") and cmd.endswith("]"):
                    continue  # kernel thread
                cmd_0 = cmd.split()[0]
                if cmd_0 == "ps":
                    continue  # ps command itself
                if self.load_baseline:
                    # learning the processes
                    base_ps = os.process_map.setdefault(user, [])
                    if cmd_0 not in base_ps:
                        base_ps.append(f"^{cmd_0}")
                    continue
                exp_ps = regexp_map.get(user) if os else None
                if exp_ps is None:
                    self.logger.debug("User %s not in process map", user)
                    continue
                for ps in exp_ps:
                    if ps.match(cmd):
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
