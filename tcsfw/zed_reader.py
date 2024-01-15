from io import BytesIO
import json
import pathlib
from datetime import datetime
from typing import List, Set

from tcsfw.address import EndpointAddress, Protocol, DNSName
from tcsfw.entity import Entity
from tcsfw.event_interface import EventInterface, PropertyAddressEvent
from tcsfw.model import IoTSystem, Service
from tcsfw.property import PropertyVerdict, Properties, PropertyKey
from tcsfw.tools import BaseFileCheckTool
from tcsfw.traffic import EvidenceSource, Evidence
from tcsfw.verdict import Verdict


class ZEDReader(BaseFileCheckTool):
    """Read ZED attack proxy scanning results for a software"""
    def __init__(self, system: IoTSystem):
        super().__init__("zed", system)
        self.tool.name = "ZED Attack Proxy"
        self.data_file_suffix = ".json"

    def read_stream(self, data: BytesIO, interface: EventInterface, source: EvidenceSource):
        raw_file = json.load(data)

        evidence = Evidence(source)

        source.timestamp = datetime.strptime(raw_file["@generated"], "%a, %d %b %Y %H:%M:%S")

        for raw in raw_file["site"]:
            host = raw["@host"]
            port = int(raw["@port"])
            ep = EndpointAddress(DNSName.name_or_ip(host), Protocol.TCP, port)
            ps = self._read_alerts(interface, evidence, ep, raw.get("alerts", []))
            exp = f"{self.tool.name} scan completed"
            ev = PropertyAddressEvent(evidence, ep, Properties.WEB_BEST.value(ps, explanation=exp))
            interface.property_address_update(ev)

    def _read_alerts(self, interface: EventInterface, evidence: Evidence, endpoint: EndpointAddress, raw: List) \
            -> Set[PropertyVerdict]:
        ps = set()
        for raw_a in raw:
            name = raw_a["name"]
            riskcode = int(raw_a["riskcode"])
            if riskcode < 2:
                self.logger.debug("Skipping riskcode < 2: %s", name)
                continue
            ref = raw_a["alertRef"]
            key = PropertyVerdict(self.tool_label, ref)
            exp = f"{self.tool.name} ({ref}): {name}"
            ev = PropertyAddressEvent(evidence, endpoint, key.value(Verdict.FAIL, exp))
            interface.property_address_update(ev)
            ps.add(key)
        return ps

    def _entity_coverage(self, entity: Entity) -> List[PropertyKey]:
        if isinstance(entity, Service) and entity.protocol in {Protocol.HTTP, Protocol.TLS}:
            return [Properties.WEB_BEST]
        return []
