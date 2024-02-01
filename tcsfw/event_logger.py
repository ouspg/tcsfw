from typing import Any, List, Set, TextIO, Tuple, Dict, Optional, cast
from tcsfw.address import AnyAddress

from tcsfw.entity import Entity
from tcsfw.event_interface import EventInterface, PropertyEvent, PropertyAddressEvent
from tcsfw.inspector import Inspector
from tcsfw.model import IoTSystem, Connection, Host, ModelListener, Service, NetworkNode
from tcsfw.property import Properties, PropertyKey
from tcsfw.services import NameEvent
from tcsfw.traffic import EvidenceSource, HostScan, ServiceScan, Flow, Event
from tcsfw.verdict import Status, Verdict


class LoggingEvent:
    """Event with logging"""
    def __init__(self, event: Event, key: Tuple[Entity, Optional[PropertyKey]] = None):
        self.event = event
        self.key = key
        self.verdict = Verdict.INCON

    def get_value_string(self) -> str:
        """Get value as string"""
        v = self.event.get_value_string()
        if self.key and (self.verdict != Verdict.INCON or self.key[0] != Status.EXPECTED):
            st = f"{self.key[0].status.value}/{self.verdict.value}" if self.verdict != Verdict.INCON  \
                else self.key[0].status.value
            v += f" [{st}]" if v else st
        return v

    def __repr__(self):
        return f"{self.key[0].long_name()}: {self.key[1] or '-'} {self.event}"


class EventLogger(EventInterface, ModelListener):
    def __init__(self, inspector: Inspector):
        self.inspector = inspector
        self.logs: List[LoggingEvent] = []
        self.current: Optional[LoggingEvent] = None  # current event
        # subscribe property events
        inspector.system.model_listeners.append(self)

    def print_events(self, writer: TextIO):
        """Print all events for debugging"""
        for lo in self.logs:
            e = lo.event
            s = ""
            if lo.key is not None:
                ent, _ = lo.key
                s = f"{ent.long_name()},"
            s = f"{s:<40}"
            s += f"{lo.get_value_string()},"
            s = f"{s:<80}"
            s += e.get_comment() or e.evidence.get_reference()
            writer.write(f"{s}\n")

    def _add(self, event: Event, entity: Entity = None, key: PropertyKey = None) -> LoggingEvent:
        """Add new current log entry"""
        if entity is None:
            ev = LoggingEvent(event)
        else:
            ev = LoggingEvent(event, (entity, key))
        self.logs.append(ev)
        self.current = ev
        return ev

    def reset(self):
        """Reset the log"""
        self.logs.clear()
        self.inspector.reset()

    def get_system(self) -> IoTSystem:
        return self.inspector.system

    def propertyChange(self, entity: Entity, value: Tuple[PropertyKey, Any]):
        if self.current is None:
            self.logger.warning("Property change without event to assign it: %s", value[0])
        # assign all property changes during an event
        ev = LoggingEvent(self.current.event, (entity, value[0]))
        self.logs.append(ev)

    def connection(self, flow: Flow) -> Connection:
        lo = self._add(flow)
        e = self.inspector.connection(flow)
        lo.key = (e, None)
        self.current = None
        return e

    def name(self, event: NameEvent) -> Host:
        e = self.inspector.name(event)
        lo = self._add(event, e)
        lo.verdict = Properties.EXPECTED.get_verdict(e.properties) or Verdict.INCON
        return e

    def property_update(self, update: PropertyEvent) -> Entity:
        e = self.inspector.property_update(update)
        self._add(update, e, update.key_value[0]) # FIXME: Leave property update for listener call
        # many properties have verdict in them
        return e

    def property_address_update(self, update: PropertyAddressEvent) -> Entity:
        e = self.inspector.property_address_update(update)
        self._add(update, e, update.key_value[0]) # FIXME: Leave property update for listener call
        # many properties have verdict in them
        return e

    def service_scan(self, scan: ServiceScan) -> Service:
        e = self.inspector.service_scan(scan)
        lo = self._add(scan, e)
        lo.verdict = Properties.EXPECTED.get_verdict(e.properties) or Verdict.INCON
        return e

    def host_scan(self, scan: HostScan) -> Host:
        e = self.inspector.host_scan(scan)
        lo = self._add(scan, e)
        lo.verdict = Properties.EXPECTED.get_verdict(e.properties) or Verdict.INCON
        return e

    def collect_flows(self) -> Dict[Connection, List[Tuple[AnyAddress, AnyAddress, Flow]]]:
        """Collect relevant connection flows"""
        r = {}
        for c in self.inspector.system.get_connections():
            r[c] = []  # expected connections without flows
        for lo in self.logs:
            event = lo.event
            if not isinstance(event, Flow):
                continue
            c = cast(Connection, lo.key[0])
            cs = r.setdefault(c, [])
            s, t = event.get_source_address(), event.get_target_address()
            cs.append((s, t, event))
        return r

    def get_log(self, entity: Optional[Entity] = None, key: Optional[PropertyKey] = None) \
            -> List[LoggingEvent]:
        """Get log, possibly filtered by entity and key"""
        ent_set = set()

        def add(n: Entity):
            ent_set.add(n)
            for c in n.get_children():
                add(c)
        if entity is not None:
            add(entity)

        r = []
        for lo in self.logs:
            if entity is not None and lo.key[0] not in ent_set:
                continue
            if key is not None and lo.key[1] != key:
                continue
            r.append(lo)
        return r

    def get_property_sources(self, entity: Entity, keys: Set[PropertyKey]) -> Dict[PropertyKey, EvidenceSource]:
        """Get property sources for an entity and set of properties"""
        r = {}
        for lo in self.logs:
            if lo.key is None or lo.key[0] != entity or lo.key[1] not in keys:
                continue
            r[lo.key[1]] = lo.event.evidence.source
        return r
