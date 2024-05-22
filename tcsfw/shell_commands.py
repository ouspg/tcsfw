"""Shell command 'ps'"""

from io import BytesIO, TextIOWrapper
import re
from typing import Dict, Tuple
from tcsfw.address import Addresses, EndpointAddress, HWAddresses, IPAddress
from tcsfw.components import OperatingSystem
from tcsfw.event_interface import EventInterface, PropertyEvent
from tcsfw.model import Addressable, IoTSystem, NetworkNode
from tcsfw.property import PropertyKey
from tcsfw.tools import NetworkNodeTool
from tcsfw.traffic import Evidence, EvidenceSource, IPFlow, Protocol, ServiceScan
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


class ShellCommandSs(NetworkNodeTool):
    """Shell command 'ss' tool adapter"""
    def __init__(self, system: IoTSystem):
        super().__init__("shell-ss", ".txt", system)

    def _parse_address(self, addr: str) -> Tuple[str, str, int]:
        """Parse address into IP, interface, port"""
        ad_inf, _, port = addr.rpartition(":")
        ad, _, inf = ad_inf.partition("%")
        return ad if ad not in {"", "*", "0.0.0.0", "[::]"} else "", inf, int(port) if port not in {"", "*"} else -1

    LOCAL_ADDRESS = "Local_Address"
    PEER_ADDRESS = "Peer_Address"

    def process_node(self, node: NetworkNode, data_file: BytesIO, interface: EventInterface, source: EvidenceSource):
        columns: Dict[str, int] = {}
        local_ads = set()
        services = set()
        conns = set()

        assert isinstance(node, Addressable)
        tag = Addresses.get_tag(node.addresses)

        with TextIOWrapper(data_file) as f:
            while True:
                line = f.readline()
                if not line:
                    break
                if not columns:
                    # header line, use first two characters (headers are truncated for narrow data)
                    line = line.replace("Local Address:Port", self.LOCAL_ADDRESS)
                    line = line.replace("Peer Address:Port", self.PEER_ADDRESS)
                    columns = {name: idx for idx, name in enumerate(line.split())}
                    assert self.LOCAL_ADDRESS in columns, "Local address not found"
                    assert self.PEER_ADDRESS in columns, "Peer address not found"
                    continue
                cols = line.split()
                if len(cols) <= columns[self.PEER_ADDRESS]:
                    continue  # bad line
                net_id = cols[columns["Netid"]]
                state = cols[columns["State"]]
                local_ip, local_inf, local_port = self._parse_address(cols[columns[self.LOCAL_ADDRESS]])
                peer_ip, _, peer_port = self._parse_address(cols[columns[self.PEER_ADDRESS]])
                self.logger.debug("Local %s:%d Peer %s:%d", local_ip, local_port, peer_ip, peer_port)
                local_add = IPAddress.new(local_ip) if local_ip else None
                peer_add = IPAddress.new(peer_ip) if peer_ip else None
                if local_inf == "lo" or (local_add and local_add.is_loopback()):
                    continue  # loopback is not external
                if not local_add:
                    if not tag:
                        continue  # no host address known, cannot send events
                    local_add = tag
                if net_id == "udp" and state == "UNCONN":
                    # listening UDP port
                    local_ads.add(local_add)
                    add = EndpointAddress(local_add or Addresses.ANY, Protocol.UDP, local_port)
                    services.add(add)
                    continue
                if net_id == "tcp" and state == "LISTEN":
                    # listening TCP port
                    local_ads.add(local_add)
                    add = EndpointAddress(local_add or Addresses.ANY, Protocol.TCP, local_port)
                    services.add(add)
                    continue
                if net_id in {"udp", "tcp"} and state != "LISTEN" and local_add and peer_add:
                    # UDP or TCP connection
                    proto = Protocol.UDP if net_id == "udp" else Protocol.TCP
                    local = EndpointAddress(local_add, proto, local_port)
                    peer = EndpointAddress(peer_add, proto, peer_port)
                    conns.add((local, peer))
                    continue

        if self.send_events:
            evidence = Evidence(source)
            for addr in sorted(services):
                scan = ServiceScan(evidence, addr)
                interface.service_scan(scan)
            # NOTE: Create host scan event to report missing services

            for conn in sorted(conns):
                s, t = conn
                if s.host in local_ads:
                    # incoming connection
                    t, s = conn
                flow = IPFlow(evidence,
                              source=(HWAddresses.NULL, s.host, s.port),
                              target=(HWAddresses.NULL, t.host, t.port),
                              protocol=s.protocol)
                interface.connection(flow)
                # these are established connections, both ways
                interface.connection(flow.reverse())
