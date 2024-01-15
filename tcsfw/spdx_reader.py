from io import BytesIO
import json
import pathlib
from datetime import datetime
from typing import cast, List

from tcsfw.components import Software, SoftwareComponent
from tcsfw.entity import Entity
from tcsfw.event_interface import PropertyEvent, EventInterface
from tcsfw.model import IoTSystem, NodeComponent
from tcsfw.property import PropertyVerdict, Properties, PropertyKey
from tcsfw.tools import ComponentCheckTool
from tcsfw.traffic import EvidenceSource, Evidence
from tcsfw.verdict import Verdict


class SPDXReader(ComponentCheckTool):
    """Read SPDX component description for a software"""
    def __init__(self, system: IoTSystem):
        super().__init__("spdx", ".json", system)
        self.tool.name = "SPDX SBOM"

    def _filter_component(self, component: NodeComponent) -> bool:
        return isinstance(component, Software)

    def process_stream(self, component: NodeComponent, data_file: BytesIO, interface: EventInterface,
                       source: EvidenceSource):
        software = cast(Software, component)

        evidence = Evidence(source)

        properties = set()

        raw_file = json.load(data_file)

        cr_info = raw_file["creationInfo"]
        source.timestamp = datetime.strptime(cr_info["created"], "%Y-%m-%dT%H:%M:%SZ")

        for index, raw in enumerate(raw_file["packages"]):
            name = raw["name"]
            if index == 0 and name.endswith(".apk"):
                continue  # NOTE A kludge to clean away opened APK itself
            version = raw.get("versionInfo", "")
            if "property 'version'" in version:
                version = ""  # NOTE: Kludging a bug in BlackDuck
            key = PropertyVerdict("component", name)
            properties.add(key)
            old_sc = software.components.get(name)
            verdict = Verdict.PASS
            if self.load_baseline:
                if old_sc:
                    self.logger.warning("Double definition for component: %s", name)
                    continue
                # component in baseline
                software.components[name] = SoftwareComponent(name, version=version)
            elif not old_sc:
                verdict = Verdict.UNEXPECTED  # unexpected claim not in baseline
            if self.send_events:
                ev = PropertyEvent(evidence, software, key.value(verdict, explanation=f"{name} {version}"))
                interface.property_update(ev)

        if self.send_events:
            ev = PropertyEvent(evidence, software, Properties.COMPONENTS.value(properties))
            interface.property_update(ev)

    def _entity_coverage(self, entity: Entity) -> List[PropertyKey]:
        if isinstance(entity, Software):
            return [Properties.COMPONENTS]
        return []
