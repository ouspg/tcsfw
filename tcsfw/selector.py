"""Requirement selectors"""

from typing import Dict, List, Optional, TypeVar, Generic, Iterator

from tcsfw.address import Addresses, Protocol
from tcsfw.basics import HostType
from tcsfw.components import StoredData, Software, DataReference
from tcsfw.entity import Entity, ExplainableClaim
from tcsfw.model import Addressable, Host, IoTSystem, NetworkNode, NodeComponent, Service, Connection
from tcsfw.property import Properties, PropertyKey
from tcsfw.requirement import Requirement, EntitySelector, SelectorContext
from tcsfw.basics import Status

S = TypeVar("S", bound='EntitySelector')


class RequirementSelector(EntitySelector):
    """Selector for a requirement"""
    def __truediv__(self, other: S) -> S:
        """Add more specific location"""
        assert isinstance(other, RequirementSelector), f"Expected location selector, got: {other}"
        return SequenceSelector([self], other)

    def __add__(self, other: 'RequirementSelector') -> 'RequirementSelector':
        return AlternativeSelectors([self, other])

    def __xor__(self, other: ExplainableClaim) -> Requirement:
        """Add the claim"""
        assert isinstance(other, ExplainableClaim), f"Expected claim, got: {other}"
        return Requirement(("", ""), other.description, self, other)


class NamedSelector(RequirementSelector):
    """A named selector"""
    def __init__(self, name: str, sub: EntitySelector):
        assert sub is not None, f"Naming null to {name}"
        self.name = name
        self.sub = sub

    def select(self, entity: Entity, context: SelectorContext) -> Iterator[Entity]:
        return self.sub.select(entity, context)

    def get_name(self) -> str:
        return self.name


class SystemSelector(RequirementSelector):
    """Select system"""
    def select(self, entity: Entity, _context: SelectorContext) -> Iterator[IoTSystem]:
        if isinstance(entity, IoTSystem):
            yield entity


class HostSelector(RequirementSelector):
    """Select hosts"""
    def __init__(self, with_unexpected=False):
        self.with_unexpected = with_unexpected

    def select(self, entity: Entity, context: SelectorContext) -> Iterator[Host]:
        """Select child entities which are hosts"""
        if isinstance(entity, Host):
            if context.include_host(entity):
                yield entity
            elif self.with_unexpected and entity.is_relevant() and entity.status == Status.UNEXPECTED:
                yield entity
        elif entity.is_host_reachable():
            for c in entity.get_children():
                yield from self.select(c, context)

    def only_concrete(self) -> 'HostSelector':
        """Select only concrete hosts"""
        parent = self

        class Selector(HostSelector):
            """The modified selector"""
            def select(self, entity: Entity, context: SelectorContext) -> Iterator[Host]:
                return (c for c in parent.select(entity, context) if c.is_concrete())
        return Selector()

    def only_server(self) -> 'HostSelector':
        """Select only server hosts"""
        parent = self

        class Selector(HostSelector):
            """The modified selector"""
            def select(self, entity: Entity, context: SelectorContext) -> Iterator[Host]:
                return (c for c in parent.select(entity, context) if c.host_type in {
                    HostType.DEVICE, HostType.GENERIC, HostType.REMOTE})
        return Selector()

    def type_of(self, *host_type: HostType) -> 'HostSelector':
        """Select by host types"""
        parent = self
        types = set(host_type)

        class Selector(HostSelector):
            """The modified selector"""
            def select(self, entity: Entity, context: SelectorContext) -> Iterator[Entity]:
                return (c for c in parent.select(entity, context) if c.host_type in types)
        return Selector()

    def with_property(self, key: PropertyKey) -> 'HostSelector':
        """Select hosts with a property"""
        parent = self

        class Selector(HostSelector):
            """The modified selector"""
            def select(self, entity: Entity, context: SelectorContext) -> Iterator[Entity]:
                return (c for c in parent.select(entity, context) if key in c.properties)
        return Selector()


class ServiceSelector(RequirementSelector):
    """Select services"""
    def __init__(self, with_unexpected=False):
        self.with_unexpected = with_unexpected

    def select(self, entity: Entity, context: SelectorContext) -> Iterator[Service]:
        if isinstance(entity, Service):
            if context.include_service(entity):
                yield entity
            elif self.with_unexpected and entity.is_relevant() and entity.status == Status.UNEXPECTED:
                # NOTE: all unexpected are included, even administrative
                yield entity
        elif entity.is_host_reachable():
            for c in entity.get_children():
                yield from self.select(c, context)

    def only_concrete(self) -> 'ServiceSelector':
        """Select services only in concrete hosts"""
        parent = self

        class Selector(ServiceSelector):
            """The modified selector"""
            def select(self, entity: Entity, context: SelectorContext) -> Iterator[Service]:
                return (c for c in parent.select(entity, context) if c.get_parent_host().is_concrete())
        return Selector()

    def authenticated(self, value=True) -> 'ServiceSelector':
        """Select authenticated services"""
        parent = self

        class Selector(ServiceSelector):
            """The modified selector"""
            def select(self, entity: Entity, context: SelectorContext) -> Iterator[Service]:
                return (c for c in parent.select(entity, context) if c.authentication == value)
        return Selector()

    def web(self) -> 'ServiceSelector':
        """Select web services"""
        parent = self

        class Selector(ServiceSelector):
            """The modified selector"""
            def select(self, entity: Entity, context: SelectorContext) -> Iterator[Service]:
                return (c for c in parent.select(entity, context) if c.protocol in {Protocol.HTTP, Protocol.TLS})
        return Selector()

    def direct(self) -> 'ServiceSelector':
        """Select direct services"""
        parent = self

        class Selector(ServiceSelector):
            """The modified selector"""
            def select(self, entity: Entity, context: SelectorContext) -> Iterator[Connection]:
                for c in parent.select(entity, context):
                    if not c.is_multicast() and Properties.HTTP_REDIRECT.get(c.properties) is None:
                        yield c
        return Selector()


class ConnectionSelector(RequirementSelector):
    """Select connections"""
    def __init__(self, with_unexpected=False):
        self.with_unexpected = with_unexpected

    def select(self, entity: Entity, context: SelectorContext) -> Iterator[Connection]:
        if isinstance(entity, Connection):
            if context.include_connection(entity):
                yield entity
            elif self.with_unexpected and entity.is_relevant() and entity.status == Status.UNEXPECTED:
                # NOTE: all unexpected are included, even administrative
                yield entity
        elif isinstance(entity, IoTSystem):
            dupes = set()
            for c in entity.get_connections():
                if c in dupes:
                    continue
                dupes.add(c)
                yield from self.select(c, context)
        elif isinstance(entity, Host):
            for c in entity.connections:
                yield from self.select(c, context)

    def encrypted(self) -> 'ConnectionSelector':
        """Select encrypted connections"""
        parent = self

        class Selector(ConnectionSelector):
            """The modified selector"""
            def select(self, entity: Entity, context: SelectorContext) -> Iterator[Connection]:
                for c in parent.select(entity, context):
                    if c.is_encrypted():
                        yield c
        return Selector()

    def authenticated(self) -> 'ConnectionSelector':
        """Select authenticated connections"""
        parent = self

        class Selector(ConnectionSelector):
            """The modified selector"""
            def select(self, entity: Entity, context: SelectorContext) -> Iterator[Connection]:
                for c in parent.select(entity, context):
                    target = c.target
                    if isinstance(target, Service) and target.authentication:
                        yield c
        return Selector()

    def protocol(self, name: str) -> 'ConnectionSelector':
        """Select connections by protocol"""
        parent = self

        class Selector(ConnectionSelector):
            """The modified selector"""
            def select(self, entity: Entity, context: SelectorContext) -> Iterator[Connection]:
                for c in parent.select(entity, context):
                    target = c.target
                    if isinstance(target, Service) and target.protocol and target.protocol.value == name:
                        yield c
        return Selector()

    def endpoint(self, endpoint: RequirementSelector) -> 'ConnectionSelector':
        """Select connections by endpoint"""
        parent = self

        class Selector(ConnectionSelector):
            """The modified selector"""
            def select(self, entity: Entity, context: SelectorContext) -> Iterator[Connection]:
                for c in parent.select(entity, context):
                    s = endpoint.select(c.source, context)
                    yield from s
                    t = endpoint.select(c.target, context)
                    yield from t
        return Selector()


class UpdateConnectionSelector(ConnectionSelector):
    """Select update connections of a software"""
    def select(self, entity: Entity, context: SelectorContext) -> Iterator[Connection]:
        for sw in SoftwareSelector().select(entity, context):
            yield from sw.update_connections


class SoftwareSelector(RequirementSelector):
    """Select software entities"""
    def select(self, entity: Entity, context: SelectorContext) -> Iterator[Software]:
        for h in HostSelector().select(entity, context):
            if not h.is_multicast():  # Multicast node does not contain software
                yield from Software.list_software(h)


class DataSelector(RequirementSelector):
    """Select data components"""
    def select(self, entity: Entity, _context: SelectorContext) -> Iterator[DataReference]:
        if not isinstance(entity, NetworkNode):
            return
        for c in entity.components:
            if isinstance(c, StoredData):
                yield from c.sub_components
        for ch in entity.children:
            yield from self.select(ch, _context)

    def personal(self, value=True) -> 'DataSelector':
        """Select personal data"""
        parent = self

        class Selector(DataSelector):
            """The modified selector"""
            def select(self, entity: Entity, context: SelectorContext) -> Iterator[DataReference]:
                return (c for c in parent.select(entity, context) if c.data.personal == value)
        return Selector()

    def passwords(self, value=True) -> 'DataSelector':
        """Select password security parameters"""
        parent = self

        class Selector(DataSelector):
            """The modified selector"""
            def select(self, entity: Entity, context: SelectorContext) -> Iterator[DataReference]:
                return (c for c in parent.select(entity, context) if c.data.password == value)
        return Selector()

    def parameters(self, value=True) -> 'DataSelector':
        """Select security parameter data"""
        # NOTE: Currently we only have private OR parameter data
        return self.personal(not value)


SS = TypeVar("SS", bound='EntitySelector')


class SequenceSelector(Generic[SS], RequirementSelector):
    """Sequence of selectors"""
    def __init__(self, pre: List[RequirementSelector], sub: SS):
        super().__init__()
        self.pre = pre
        self.sub = sub

    def select(self, entity: Entity, context: SelectorContext) -> Iterator[SS]:
        e_set = [entity]
        for s in self.pre:
            n_set = []
            for e in e_set:
                n_set.extend(s.select(e, context))
            if not n_set:
                return
            e_set = n_set
        for e in e_set:
            yield from self.sub.select(e, context)

    def __truediv__(self, other: S) -> S:
        pre = self.pre.copy()
        pre.append(self.sub)
        return SequenceSelector(pre, other)


class AlternativeSelectors(RequirementSelector):
    """Alternative selectors"""
    def __init__(self, sub: List[RequirementSelector]):
        super().__init__()
        self.sub = sub

    def __add__(self, other: RequirementSelector) -> 'AlternativeSelectors':
        return AlternativeSelectors(self.sub + [other])

    def select(self, entity: Entity, context: SelectorContext) -> Iterator[Entity]:
        for s in self.sub:
            yield from s.select(entity, context)


class Select:
    """Factory for selectors"""
    @classmethod
    def host(cls, unexpected=False) -> HostSelector:
        """Select hosts"""
        return HostSelector(unexpected)

    @classmethod
    def service(cls, unexpected=False) -> ServiceSelector:
        """Select services"""
        return ServiceSelector(unexpected)

    @classmethod
    def connection(cls, unexpected=False) -> ConnectionSelector:
        """Select connections"""
        return ConnectionSelector(unexpected)

    @classmethod
    def system(cls) -> SystemSelector:
        """Select the system"""
        return cls.SYSTEM_SINGLE  # singleton now

    @classmethod
    def software(cls) -> SoftwareSelector:
        """Select software"""
        return cls.SOFTWARE_SINGLE # singleton now

    @classmethod
    def data(cls) -> DataSelector:
        """Select data"""
        return DataSelector()

    SYSTEM_SINGLE = SystemSelector()
    SOFTWARE_SINGLE = SoftwareSelector()


class Finder:
    """Find entities by specifiers"""

    @classmethod
    def find(cls, system: IoTSystem, specifier: Dict) -> Optional[Entity]:
        """Find entity by JSON specifier"""
        entity = None
        addr_s = specifier.get("system")
        if addr_s:
            entity = system
        if not entity:
            addr_s = specifier.get("address")
            if addr_s:
                addr = Addresses.parse_endpoint(addr_s)
                entity = system.find_endpoint(addr)
                if not entity:
                    raise ValueError(f"Cannot find entity: {addr_s}")
        if not entity:
            add_r = specifier.get("connection")
            if add_r:
                addrs = [Addresses.parse_endpoint(a) for a in add_r]
                s = system.find_endpoint(addrs[0])
                if not s:
                    raise ValueError(f"Cannot find connection source: {add_r}")
                t = system.find_endpoint(addrs[1])
                if not t:
                    raise ValueError(f"Cannot find connection target: {add_r}")
                entity = s.find_connection(t)
        comp_s = specifier.get("software")
        if comp_s:
            if not entity:
                raise ValueError(f"Cannot find software without entity: {comp_s}")
            entity = Software.get_software(entity, comp_s)
            if not entity:
                raise ValueError(f"Cannot find software: {comp_s}")
            return entity
        data_s = specifier.get("data")
        if data_s:
            if not entity:
                raise ValueError(f"Cannot find data without entity: {comp_s}")
            store = StoredData.find_data(entity)
            entity = next(r for r in store.sub_components if r.data.name == data_s)
            if not entity:
                raise ValueError(f"Cannot find data: {comp_s}")
            return entity
        # NOTE: OS and oter components - needs unified way to access
        return entity

    @classmethod
    def specify(cls, entity: Entity) -> Dict:
        """Create JSON specifier for entity"""
        r = {}
        ent = entity
        if isinstance(entity, NodeComponent):
            ent = entity.entity
            r[entity.concept_name] = entity.name
        if isinstance(ent, IoTSystem):
            r["system"] = True
        elif isinstance(ent, Addressable):
            tag = ent.get_tag()
            if tag is None:
                raise ValueError(f"Cannot specify entity without tag: {ent}")
            r["address"] = tag.get_parseable_value()
        elif isinstance(ent, Connection):
            tag = ent.get_tag()
            if tag is None:
                raise ValueError(f"Cannot specify connection without both tags: {ent}")
            r["connection"] = [t.get_parseable_value() for t in tag]
        else:
            raise ValueError(f"Cannot specify entity: {entity}")
        return r
