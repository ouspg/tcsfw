import argparse
import io
import ipaddress
import itertools
import json
import logging
import pathlib
import sys
from typing import Any, Callable, Dict, List, Optional, Self, Tuple, Type, Union

from tcsfw.address import (Addresses, AnyAddress, DNSName, EndpointAddress,
                           HWAddress, HWAddresses, IPAddress, IPAddresses,
                           Protocol)
from tcsfw.batch_import import BatchImporter, LabelFilter
from tcsfw.claim import Claim
from tcsfw.claim_coverage import RequirementClaimMapper
from tcsfw.client_api import APIRequest
from tcsfw.components import (CookieData, Cookies, DataReference, DataStorages,
                              Software)
from tcsfw.coverage_result import CoverageReport
from tcsfw.entity import ClaimAuthority, Entity
from tcsfw.event_interface import PropertyEvent
from tcsfw.events import ReleaseInfo
from tcsfw.http_server import HTTPServerRunner
from tcsfw.inspector import Inspector
from tcsfw.latex_output import LaTeXGenerator
from tcsfw.main_basic import (BuilderInterface, SubLoader)
from tcsfw.main_tools import EvidenceLoader, ToolPlanLoader
from tcsfw.model import (Addressable, Connection, ConnectionType,
                         ExternalActivity, Host, HostType, IoTSystem, SensitiveData,
                         Service)
from tcsfw.property import Properties, PropertyKey
from tcsfw.registry import Registry
from tcsfw.result import Report
from tcsfw.selector import RequirementSelector
from tcsfw.services import DHCPService, DNSService
from tcsfw.traffic import Evidence, EvidenceSource
from tcsfw.verdict import Status, Verdict
from tcsfw.visualizer import Visualizer, VisualizerAPI


class SystemBuilder:
    """System model builder"""
    def network(self, mask: str) -> Self:
        raise NotImplementedError()

    def device(self, name="") -> 'HostBuilder':
        """IoT device"""
        raise NotImplementedError()

    def backend(self, name="") -> 'HostBuilder':
        """Backend service"""
        raise NotImplementedError()

    def mobile(self, name="") -> 'HostBuilder':
        """Mobile device"""
        raise NotImplementedError()

    def browser(self, name="") -> 'HostBuilder':
        """Browser"""
        raise NotImplementedError()

    def any(self, name="", node_type: HostType = None) -> 'HostBuilder':
        """Any host"""
        raise NotImplementedError()

    def infra(self, name="") -> 'HostBuilder':
        """Part of the testing infrastructure, not part of the system itself"""
        raise NotImplementedError()

    def multicast(self, address: str, protocol: 'ProtocolConfigurer') -> 'ServiceBuilder':
        """IP multicast target"""
        raise NotImplementedError()

    def broadcast(self, protocol: 'ProtocolConfigurer') -> 'ServiceBuilder':
        """IP broadcast target"""
        raise NotImplementedError()

    def data(self, names: List[str], personal=False, password=False) -> 'SensitiveDataBackend':
        """Declare pieces of security-relevant data"""
        raise NotImplementedError()

    def online_resource(self, key: str, url: str) -> Self:
        """Document online resource"""
        raise NotImplementedError()

    def visualize(self) -> 'VisualizerBackend':
        raise NotImplementedError()

    def load(self) -> 'EvidenceLoader':
        raise NotImplementedError()

    def claims(self, base_label="explain") -> 'ClaimSetBuilder':
        raise NotImplementedError()


# Host types
BROWSER = HostType.BROWSER

# Connection types
ADMINISTRATIVE = ConnectionType.ADMINISTRATIVE
ENCRYPTED = ConnectionType.ENCRYPTED
PLAINTEXT = ConnectionType.UNKNOWN


# External activity
BANNED = ExternalActivity.BANNED
PASSIVE = ExternalActivity.PASSIVE
OPEN = ExternalActivity.OPEN
UNLIMITED = ExternalActivity.UNLIMITED


ProtocolType = Union['ProtocolConfigurer', Type['ProtocolConfigurer']]
ServiceOrGroup = Union['ServiceBuilder', 'ServiceGroupBuilder']


class NodeBuilder:
    def __init__(self, system: SystemBuilder):
        # NOTE: This is not called from subclasses, necessarily
        self.system = system

    def name(self, name: str) -> Self:
        """Define entity name, names with dot (.) are assumed to be DNS domain names"""
        raise NotImplementedError()

    def dns(self, name: str) -> Self:
        """Define DNS name"""
        raise NotImplementedError()

    def describe(self, text: str) -> Self:
        """Describe the system by a few sentences."""
        raise NotImplementedError()

    def external_activity(self, value: ExternalActivity) -> Self:
        raise NotImplementedError()

    def software(self, name: Optional[str] = None) -> 'SoftwareBackend':
        raise NotImplementedError()

    def visual(self) -> 'NodeVisualBackend':
        """Create visual for the host"""
        raise NotImplementedError()

    def __rshift__(self, target: ServiceOrGroup) -> 'ConnectionBackend':
        raise NotImplementedError()


class ServiceBuilder(NodeBuilder):
    """Service builder"""
    def __init__(self, system: SystemBuilder):
        super().__init__(system)

    def type(self, value: ConnectionType) -> Self:
        """Configure connection type"""
        raise NotImplementedError()

    def authenticated(self, flag: bool) -> Self:
        """Is this service authenticated?"""
        raise NotImplementedError()

    def __truediv__(self, protocol: ProtocolType) -> 'ServiceGroupBuilder':
        """Pick or add the configured protocol to host"""
        raise NotImplementedError()


class ServiceGroupBuilder:
    """One or more services grouped"""
    def __truediv__(self, other: ServiceOrGroup | ProtocolType) -> Self:
        raise NotImplementedError()


class HostBuilder(NodeBuilder):
    """Host builder"""
    def __init__(self, system: SystemBuilder):
        NodeBuilder.__init__(self, system)

    def hw(self, address: str) -> Self:
        """Add HW address"""
        raise NotImplementedError()

    def ip(self, address: str) -> Self:
        """Add IP address"""
        raise NotImplementedError()

    def serve(self, *protocols: ProtocolType) -> Self:
        """Serve the configured protocol or protocols"""
        raise NotImplementedError()

    def __lshift__(self, multicast: ServiceBuilder) -> 'ConnectionBackend':
        """Receive broadcast or multicast"""
        raise NotImplementedError()

    def cookies(self) -> 'CookieBuilder':
        """Configure cookies in a browser"""
        raise NotImplementedError()

    def use_data(self, *data: 'SensitiveDataBackend') -> Self:
        """This host uses some sensitive data"""
        raise NotImplementedError()

    def __truediv__(self, protocol: ProtocolType) -> ServiceBuilder:
        """Pick or add the configured protocol"""
        raise NotImplementedError()

    def ignore_name_requests(self, *name: str) -> Self:
        """Ignore DNS name requests for these names"""
        raise NotImplementedError()

    def set_property(self, *key: str):
        """Set a model properties"""
        raise NotImplementedError()


class SensitiveDataBuilder:
    """Sensitive data builder"""
    def __init__(self, parent: SystemBuilder):
        self.parent = parent

    def used_by(self, *host: HostBuilder) -> Self:
        """This data used/stored in a host"""
        raise NotImplementedError()

    def authorize(self, *service: ServiceBuilder) -> Self:
        """This data is used for service authentication"""
        raise NotImplementedError()


class ConnectionBuilder:
    """Connection builder"""
    def logical_only(self) -> Self:
        """Only a logical link"""
        raise NotImplementedError()


class SoftwareBuilder:
    """Software builder"""
    def updates_from(self, source: Union[ConnectionBuilder, ServiceBuilder, HostBuilder]) -> Self:
        """Update mechanism"""
        raise NotImplementedError()

    def first_release(self, date: str) -> Self:
        """First release as YYYY-MM-DD"""
        raise NotImplementedError()

    def supported_until(self, date: str) -> Self:
        """Support end time YYYY-MM-DD"""
        raise NotImplementedError()

    def update_frequency(self, days: float) -> Self:
        """Target update frequency, days"""
        raise NotImplementedError()


class CookieBuilder:
    """Cookies in a browser"""
    def set(self, cookies: Dict[str, Tuple[str, str, str]]):
        """Set cookies, name: domain, path, explanation"""
        raise NotImplementedError()


class NodeVisualBuilder:
    """Visual builder for a network node"""
    def hide(self) -> Self:
        raise NotImplementedError()

    def image(self, url: str, scale=100) -> Self:
        raise NotImplementedError()


class VisualizerBuilder:
    """Visual builder"""
    def place(self, *places: str) -> Self:
        """Place handles into image"""
        raise NotImplementedError()

    def where(self, handles: Dict[str, Union[NodeBuilder, NodeVisualBuilder]]) -> Self:
        """Name handles in the image"""
        raise NotImplementedError()


class ProtocolConfigurer:
    """Protocol configurer base class"""
    def __init__(self, name: str):
        self.name = name

    def __repr__(self) -> str:
        return self.name


class ARP(ProtocolConfigurer):
    def __init__(self):
        ProtocolConfigurer.__init__(self, "ARP")


class DHCP(ProtocolConfigurer):
    def __init__(self, port=67):
        ProtocolConfigurer.__init__(self, "DHCP")
        self.port = port


class DNS(ProtocolConfigurer):
    def __init__(self, port=53, captive=False):
        ProtocolConfigurer.__init__(self, "DNS")
        self.port = port
        self.captive = captive

class EAPOL(ProtocolConfigurer):
    def __init__(self):
        ProtocolConfigurer.__init__(self, "EAPOL")


class HTTP(ProtocolConfigurer):
    def __init__(self, port=80, auth: Optional[bool] = None):
        ProtocolConfigurer.__init__(self, "HTTP")
        self.port = port
        self.auth = auth
        self.redirect_only = False

    def redirect(self) -> Self:
        """This is only HTTP redirect to TLS"""
        self.redirect_only = True
        return self


class ICMP(ProtocolConfigurer):
    def __init__(self):
        ProtocolConfigurer.__init__(self, "ICMP")


class IP(ProtocolConfigurer):
    def __init__(self, name="IP", administration=False):
        ProtocolConfigurer.__init__(self, name)
        self.administration = administration


class TLS(ProtocolConfigurer):
    def __init__(self, port=443, auth: Optional[bool] = None):
        ProtocolConfigurer.__init__(self, "TLS")
        self.port = port
        self.auth = auth


class NTP(ProtocolConfigurer):
    def __init__(self, port=123):
        ProtocolConfigurer.__init__(self, "NTP")
        self.port = port


class SSH(ProtocolConfigurer):
    def __init__(self, port=22):
        ProtocolConfigurer.__init__(self, "SSH")
        self.port = port


class TCP(ProtocolConfigurer):
    def __init__(self, port: int, name="TCP", administrative=False):
        ProtocolConfigurer.__init__(self, name)
        self.port = port
        self.name = name
        self.administrative = administrative


class UDP(ProtocolConfigurer):
    def __init__(self, port: int, name="UDP", administrative=False):
        ProtocolConfigurer.__init__(self, name)
        self.port = port
        self.name = name
        self.administrative = administrative


class BLEAdvertisement(ProtocolConfigurer):
    def __init__(self, event_type: int):
        ProtocolConfigurer.__init__(self, "BLE Ad")
        self.event_type = event_type


class ClaimBuilder:
    """Claim builder"""
    def key(self, *segments: str) -> Self:
        """Add property key"""
        raise NotImplementedError()

    def keys(self, *key: Tuple[str, ...]) -> Self:
        """Add property keys"""
        raise NotImplementedError()

    def verdict_ignore(self) -> Self:
        """Override verdict to ignore"""
        raise NotImplementedError()

    def verdict_pass(self) -> Self:
        """Override verdict to pass"""
        raise NotImplementedError()

    def at(self, *locations: Union[SystemBuilder, NodeBuilder, ConnectionBuilder]) -> 'Self':
        """Set claimed location(s)"""
        raise NotImplementedError()

    def software(self, *locations: NodeBuilder) -> 'Self':
        """Claims for software in the locations"""
        raise NotImplementedError()

    def claims(self, *claims: Union[Claim, Tuple[str, str]]) -> Self:
        """Add extended claims"""
        raise NotImplementedError()

    def vulnerabilities(self, *entry: Tuple[str, str]) -> Self:
        """Explain CVE-entries"""
        raise NotImplementedError()


class ClaimSetBuilder:
    """Builder for set of claims"""
    def set_base_label(self, base_label: str) -> Self:
        """Set label for the claims"""
        raise NotImplementedError()

    def claim(self, explanation: str, verdict=Verdict.PASS) -> ClaimBuilder:
        """Self-made claims"""
        raise NotImplementedError()

    def reviewed(self, explanation="", verdict=Verdict.PASS) -> ClaimBuilder:
        """Make reviewed claims"""
        raise NotImplementedError()

    def ignore(self, explanation="") -> ClaimBuilder:
        """Ignore claims or requirements"""
        raise NotImplementedError()

    def plan_tool(self, tool_name: str, group: Tuple[str, str], location: RequirementSelector,
                  *key: Tuple[str, ...]):
        """Plan use of a tool using the property keys it is supposed to set"""
        raise NotImplementedError()


class Builder:
    """Factory for creating builders"""
    @classmethod
    def new(cls, name="Unnamed system") -> SystemBuilder:
        """Create a new system builder"""
        from tcsfw.builder_backend import SystemBackendRunner  # avoid circular import
        return SystemBackendRunner(name)

##
## FIXME: Backend files temporary located below to avoid circual imports
##

class SystemBackend(SystemBuilder):
    """System model builder"""
    def __init__(self, name="Unnamed system"):
        self.system = IoTSystem(name)
        self.hosts_by_name: Dict[str, 'HostBackend'] = {}
        self.entity_by_address: Dict[AnyAddress, 'NodeBackend'] = {}
        self.network_masks = []
        self.claimSet = ClaimSetBackend(self)
        self.visualizer = Visualizer()
        self.loaders: List['EvidenceLoader'] = []
        self.protocols: Dict[Any, 'ProtocolBackend'] = {}

    def network(self, mask: str) -> Self:
        self.network_masks.append(ipaddress.ip_network(mask))
        self.system.ip_networks = self.network_masks
        return self

    def device(self, name="") -> 'HostBackend':
        name = name or self._free_host_name("Device")
        b = self.get_host_(name, "Internet Of Things device")
        b.entity.host_type = HostType.DEVICE
        return b

    def backend(self, name="") -> 'HostBackend':
        name = name or self._free_host_name("Backend")
        b = self.get_host_(name, "Backend service over Internet")
        b.entity.host_type = HostType.REMOTE
        return b

    def mobile(self, name="") -> 'HostBackend':
        name = name or self._free_host_name("Mobile")
        b = self.get_host_(name, "Mobile application")
        b.entity.host_type = HostType.MOBILE
        b.entity.external_activity = ExternalActivity.UNLIMITED  # who know what apps etc.
        return b

    def browser(self, name="") -> 'HostBackend':
        name = name or self._free_host_name("Browser")
        b = self.get_host_(name, "Browser")
        b.entity.host_type = HostType.BROWSER
        return b

    def any(self, name="", node_type: HostType = None) -> 'HostBackend':
        name = name or self._free_host_name("Host")
        b = self.get_host_(name, "Any host")
        b.entity.any_host = True
        b.entity.host_type = HostType.ADMINISTRATIVE if node_type is None else node_type
        # might serve other network nodes
        b.entity.external_activity = ExternalActivity.UNLIMITED
        return b

    def infra(self, name="") -> 'HostBackend':
        name = name or self._free_host_name("Infra")
        b = self.get_host_(name, "Part of the testing infrastructure")
        b.entity.host_type = HostType.ADMINISTRATIVE
        b.entity.external_activity = ExternalActivity.UNLIMITED
        b.entity.match_priority = 5
        return b

    def multicast(self, address: str, protocol: 'ProtocolConfigurer') -> 'ServiceBackend':
        conf = self.get_protocol_backend(protocol)
        return conf.as_multicast_(address, self)

    def broadcast(self, protocol: 'ProtocolConfigurer') -> 'ServiceBackend':
        conf = self.get_protocol_backend(protocol)
        add = f"{IPAddresses.BROADCAST}" if conf.transport == Protocol.UDP else f"{HWAddresses.BROADCAST}"
        return self.multicast(add, protocol)

    def data(self, names: List[str], personal=False, password=False) -> 'SensitiveDataBackend':
        d = [SensitiveData(n, personal=personal, password=password) for n in names]
        return SensitiveDataBackend(self, d)

    def online_resource(self, key: str, url: str) -> Self:
        self.system.online_resources[key] = url
        return self

    def visualize(self) -> 'VisualizerBackend':
        return VisualizerBackend(self.visualizer)

    def load(self) -> 'EvidenceLoader':
        el = EvidenceLoader(self)
        self.loaders.append(el)
        return el

    def claims(self, base_label="explain") -> 'ClaimSetBackend':
        self.claimSet.base_label = base_label
        return self.claimSet

    ### Backend methods

    def get_host_(self, name: str, description: str) -> 'HostBackend':
        """Get or create a host"""
        hb = self.hosts_by_name.get(name)
        if hb is None:
            h = Host(self.system, name)
            h.description = description
            h.match_priority = 10
            hb = HostBackend(h, self)
        return hb

    def get_protocol_backend(self, protocol: 'ProtocolConfigurer' | ProtocolType) -> 'ProtocolBackend':
        """Get protocol backend, create if required"""
        be = self.protocols.get(protocol)
        if be is None:
            if isinstance(protocol, ProtocolConfigurer):
                p = protocol
            else:
                p = protocol()
            assert isinstance(p, ProtocolConfigurer), f"Not protocol type: {p.__class__.__name__}"
            be = self.protocols[p] = ProtocolBackend.new(p)
        return be

    def _free_host_name(self, name_base: str) -> str:
        n = self.system.free_child_name(name_base)
        if n != name_base:
            # dirty hack, check all names match keys
            self.hosts_by_name = {h.entity.name: h for h in self.hosts_by_name.values()}
        return n

    def finish_(self):
        """Finish the model"""
        # We want to have a authenticator related to each authenticated service
        return
        # NOTE: Not ready to go into this level now...
        # auth_map = DataUsage.map_authenticators(self.system, {})
        # for hb in self.hosts_by_name.values():
        #     for sb in hb.service_builders.values():
        #         s = sb.entity
        #         if s not in auth_map and s.authentication:
        #             auth = PieceOfData(f"Auth-{s.name}")  # default authenticator
        #             auth.authenticator_for.append(s)
        #             hb.use_data(DataPieceBuilder(self, [auth]))
        #             # property to link from service to authentication
        #             exp = f"Authentication by {auth.name} (implicit)"
        #             prop_v = Properties.AUTHENTICATION_DATA.value(explanation=exp)
        #             prop_v[0].set(s.properties, prop_v[1])


class NodeBackend:
    def __init__(self, entity: Addressable, system: SystemBackend):
        self.system = system
        self.entity = entity
        self.parent: Optional[NodeBackend] = None
        self.sw: Dict[str, SoftwareBackend] = {}
        system.system.originals.add(entity)

    def name(self, name: str) -> Self:
        self.entity.name = name
        if DNSName.looks_like(name):
            self.dns(name)
        return self

    def dns(self, name: str) -> Self:
        dn = DNSName(name)
        if dn in self.system.entity_by_address:
            raise Exception(f"Using name many times: {dn}")
        self.system.entity_by_address[dn] = self
        self.entity.addresses.add(dn)
        return self

    def describe(self, text: str) -> Self:
        """Describe the system by a few sentences."""
        self.entity.description = text
        return self

    def external_activity(self, value: ExternalActivity) -> Self:
        self.entity.set_external_activity(value)
        return self

    def software(self, name: Optional[str] = None) -> 'SoftwareBackend':
        if name is None:
            name = Software.default_name(self.entity)
        sb = self.sw.get(name)
        if sb is None:
            sb = SoftwareBackend(self, name)
            self.sw[name] = sb
        return sb

    def visual(self) -> 'NodeVisualBackend':
        p = self
        while p.parent:
            p = p.parent
        return NodeVisualBackend(p)

    def __rshift__(self, target: ServiceOrGroup) -> 'ConnectionBackend':
        if isinstance(target, ServiceGroupBackend):
            c = None
            for t in target.services:
                c = t.connection_(self)
            return c
        else:
            return target.connection_(self)

    ### Backend methods

    def new_address_(self, address: AnyAddress) -> AnyAddress:
        """Add new address to the entity"""
        old = self.system.entity_by_address.get(address)
        if old:
            raise Exception(f"Duplicate address {address}, reserved by: {old.entity.name}")
        self.entity.addresses.add(address)
        self.system.entity_by_address[address] = self
        return address

    def new_service_(self, name: str, port=-1):
        """Create new service here"""
        return Service(Service.make_name(name, port), self.entity)

    def get_software(self) -> Software:
        return self.software().sw

    def __repr__(self):
        return self.entity.__repr__()


class ServiceBackend(NodeBackend,ServiceBuilder):
    def __init__(self, host: 'HostBackend', service: Service):
        NodeBackend.__init__(self, service, host.system)
        self.entity = service
        self.configurer: Optional[ProtocolConfigurer] = None
        self.entity.match_priority = 10
        self.entity.external_activity = host.entity.external_activity
        self.parent = host
        self.source_fixer: Optional[Callable[['HostBackend'], 'ServiceBackend']] = None

    def type(self, value: ConnectionType) -> 'ServiceBackend':
        # FIXME: We should block defining plaintext connection as admin?
        self.entity.con_type = value
        return self

    def authenticated(self, flag: bool) -> Self:
        self.entity.authentication = flag
        return self

    def __truediv__(self, protocol: ProtocolType) -> 'ServiceGroupBackend':
        s = self.parent / protocol
        return ServiceGroupBackend([self, s])

    ### Backend methods

    def connection_(self, source: 'NodeBackend') -> 'ConnectionBackend':
        s = source
        if self.source_fixer:
            assert isinstance(s, HostBackend)
            s = self.source_fixer(s)
        for c in s.entity.get_parent_host().connections:
            if c.source == s.entity and c.target == self.entity:
                # referring existing connection
                return ConnectionBackend(c, (s, self))
        c = Connection(s.entity, self.entity)
        c.status = Status.EXPECTED
        c.con_type = self.entity.con_type
        for e in [s.entity, self.entity]:
            e.status = Status.EXPECTED
        s.entity.get_parent_host().connections.append(c)
        self.entity.get_parent_host().connections.append(c)
        return ConnectionBackend(c, (s, self))


class ServiceGroupBackend(ServiceGroupBuilder):
    def __init__(self, services: List[ServiceBackend]):
        assert len(services) > 0, "Empty list of services"
        self.services = services

    def __truediv__(self, other: ServiceOrGroup | ProtocolType) -> 'ServiceGroupBackend':
        g = self.services.copy()
        if isinstance(other, ServiceGroupBackend):
            g.extend(other.services)
        elif isinstance(other, ServiceBackend):
            g.append(other)
        else:
            system = self.services[0].system
            conf = system.get_protocol_backend(other)
            g.append(conf.get_service_(self.services[0].parent))
        return ServiceGroupBackend(g)

    ### Backend methods

    def __repr__(self):
        return " / ".join([f"{s.entity.name}" for s in self.services])


class HostBackend(NodeBackend,HostBuilder):
    def __init__(self, entity: Host, system: SystemBackend):
        NodeBackend.__init__(self, entity, system)
        self.entity = entity
        system.system.children.append(entity)
        entity.status = Status.EXPECTED
        system.hosts_by_name[entity.name] = self
        if DNSName.looks_like(entity.name):
            self.name(entity.name)
        self.service_builders: Dict[Tuple[Protocol, int], ServiceBackend] = {}

    def hw(self, address: str) -> 'HostBackend':
        add = self.new_address_(HWAddress.new(address))
        return self

    def ip(self, address: str) -> 'HostBackend':
        add = self.new_address_(IPAddress.new(address))
        return self

    def serve(self, *protocols: ProtocolType) -> Self:
        for p in protocols:
            self / p
        return self

    def __lshift__(self, multicast: ServiceBackend) -> 'ConnectionBackend':
        mc = multicast.entity
        assert mc.is_multicast(), "Can only receive multicast"
        # no service created, just connection from this to the multicast node
        c = self >> multicast
        c.logical_only()
        return c

    def cookies(self) -> 'CookieBackend':
        return CookieBackend(self)

    def use_data(self, *data: 'SensitiveDataBackend') -> Self:
        usage = DataStorages.get_storages(self.entity, add=True)
        for db in data:
            for d in db.data:
                usage.sub_components.append(DataReference(usage, d))
        return self

    def __truediv__(self, protocol: ProtocolType) -> ServiceBackend:
        conf = self.system.get_protocol_backend(protocol)
        return conf.get_service_(self)

    def ignore_name_requests(self, *name: str) -> Self:
        self.entity.ignore_name_requests.update([DNSName(n) for n in name])
        return self

    def set_property(self, *key: str):
        p = PropertyKey.create(key).persistent()
        self.entity.set_property(p.verdict())  # inconclusive
        return self


class SensitiveDataBackend(SensitiveDataBuilder):
    def __init__(self, parent: SystemBackend, data: List[SensitiveData]):
        self.parent = parent
        self.data = data
        # all sensitive data lives at least in system
        usage = DataStorages.get_storages(parent.system, add=True)
        for d in data:
            usage.sub_components.append(DataReference(usage, d))

    def used_by(self, *host: HostBackend) -> Self:
        for h in host:
            h.use_data(self)
        return self

    def authorize(self, *service: ServiceBackend) -> Self:
        for s in service:
            s.parent.use_data(self)
            for d in self.data:
                d.authenticator_for.append(s.entity)
                # property to link from service to authentication
                prop_v = Properties.AUTHENTICATION_DATA.value(explanation=d.name)
                prop_v[0].set(s.entity.properties, prop_v[1])
        return self


class ConnectionBackend(ConnectionBuilder):
    def __init__(self, connection: Connection, ends: Tuple[NodeBackend, ServiceBackend]):
        self.connection = connection
        self.ends = ends
        self.ends[0].system.system.originals.add(connection)

    def logical_only(self) -> Self:
        self.connection.con_type = ConnectionType.LOGICAL
        return self

    def __repr__(self):
        return self.connection.__repr__()


class SoftwareBackend(SoftwareBuilder):
    def __init__(self, parent: NodeBackend, software_name: str):
        self.sw: Software = Software.get_software(parent.entity, software_name)
        if self.sw is None:
            self.sw = Software(parent.entity, software_name)
            parent.entity.add_component(self.sw)
        self.parent = parent

    def updates_from(self, source: Union[ConnectionBackend, ServiceBackend, HostBackend]) -> Self:
        host = self.parent.entity

        cs = []
        if isinstance(source, HostBackend):
            end = source.entity
            for c in host.get_connections():
                if c.source.get_parent_host() == end or c.target.get_parent_host() == end:
                    cs.append(c)
        else:
            raise NotImplementedError("Only support updates_by host implemented")
        if not cs:
            raise Exception(f"No connection between {self.parent} - {source}")
        if len(cs) != 1:
            raise Exception(f"Several possible connections between {self.parent} - {source}")
        self.sw.update_connections.extend(cs)
        return self

    def first_release(self, date: str) -> Self:
        """First release as YYYY-MM-DD"""
        self.sw.info.first_release = ReleaseInfo.parse_time(date)
        return self

    def supported_until(self, date: str) -> Self:
        """Support end time YYYY-MM-DD"""
        # FIXME EndOfSupport(ReleaseInfo.parse_time(date))
        return self

    def update_frequency(self, days: float) -> Self:
        """Target update frequency, days"""
        self.sw.info.interval_days = days
        return self

    ### Backend methods

    def get_software(self, name: Optional[str] = None) -> Software:
        return self.sw


class CookieBackend(CookieBuilder):
    def __init__(self, builder: HostBackend):
        self.builder = builder
        self.component = Cookies.cookies_for(builder.entity)

    def set(self, cookies: Dict[str, Tuple[str, str, str]]):
        for name, p in cookies.items():
            self.component.cookies[name] = CookieData(p[0], p[1], p[2])


class NodeVisualBackend(NodeVisualBuilder):
    def __init__(self, entity: NodeBackend):
        self.entity = entity
        self.image_url: Optional[str] = None
        self.image_scale: int = 100

    def hide(self) -> Self:
        self.entity.entity.visual = False
        return self

    def image(self, url: str, scale=100) -> Self:
        self.image_url = url
        self.image_scale = scale
        return self


class VisualizerBackend(VisualizerBuilder):
    """Visual builder"""
    def __init__(self, visualizer: Visualizer):
        self.visualizer = visualizer

    def place(self, *places: str) -> Self:
        self.visualizer.placement = places
        return self

    def where(self, handles: Dict[str, Union[NodeBackend, NodeVisualBackend]]) -> Self:
        for h, b in handles.items():
            if isinstance(b, NodeVisualBackend):
                ent = b.entity.entity.get_parent_host()
                if b.image_url:
                    self.visualizer.images[ent] = b.image_url, b.image_scale
            else:
                ent = b.entity.get_parent_host()
            self.visualizer.handles[h] = ent
        return self


class ProtocolBackend:
    """Protocol configurer backend"""
    @classmethod
    def new(cls, configurer: ProtocolConfigurer) -> 'ProtocolBackend':
        pt = configurer.__class__
        pt_cre = ProtocolConfigurers.Constructors.get(pt)
        if pt_cre is None:
            raise NotImplemented(f"No backend mapped for {pt}")
        be = pt_cre(configurer)
        return be

    def __init__(self, transport: Optional[Protocol] = None, protocol: Protocol = Protocol.ANY, name="", port=-1):
        self.transport = transport
        self.protocol = protocol
        self.service_name = name
        self.port_to_name = True
        self.service_port = port
        self.host_type = HostType.GENERIC
        self.con_type = ConnectionType.UNKNOWN
        self.authentication = False
        self.external_activity: Optional[ExternalActivity.BANNED] = None
        self.critical_parameter: List[SensitiveData] = []

    def as_multicast_(self, address: str, system: SystemBackend) -> ServiceBackend:
        """The protocol as multicast"""
        raise NotImplementedError(f"{self.service_name} cannot be broad/multicast")

    def get_service_(self, parent: HostBackend) -> ServiceBackend:
        """Create or get service builder"""
        old = parent.service_builders.get((self.transport, self.service_port if self.port_to_name else -1))
        if old:
            return old
        b = self._create_service(parent)
        parent.service_builders[(self.transport, self.service_port)] = b
        b.entity.status = Status.EXPECTED
        assert b.entity.parent == parent.entity
        parent.entity.children.append(b.entity)
        if not b.entity.addresses:
            # E.g. DHCP service fills this oneself
            b.entity.addresses.add(EndpointAddress(Addresses.ANY, self.transport, self.service_port))
        if self.critical_parameter:
            parent.use_data(SensitiveDataBackend(parent.system, self.critical_parameter))  # critical protocol parameters
        return b

    def _create_service(self, parent: HostBackend) -> ServiceBackend:
        s = ServiceBackend(parent,
                           parent.new_service_(self.service_name, self.service_port if self.port_to_name else -1))
        s.configurer = self
        s.entity.authentication = self.authentication
        s.entity.host_type = self.host_type
        s.entity.con_type = self.con_type
        if self.external_activity is not None:
            s.entity.external_activity = self.external_activity
        s.entity.protocol = self.protocol
        return s

    def __repr__(self):
        return f"{self.service_name}"


class ARPBackend(ProtocolBackend):
    def __init__(self, configurer: ARP, broadcast_endpoint=False):
        super().__init__(Protocol.ARP, name="ARP")
        self.host_type = HostType.ADMINISTRATIVE
        self.con_type = ConnectionType.ADMINISTRATIVE
        self.broadcast_endpoint = broadcast_endpoint
        # ARP make requests and replies
        self.external_activity = ExternalActivity.UNLIMITED

    def get_service_(self, parent: HostBackend) -> ServiceBackend:
        if self.broadcast_endpoint:
            return super().get_service_(parent)
        host_s = super().get_service_(parent)
        # ARP can be broadcast, get or create the broadcast host and service
        bc_node = parent.system.get_host_(f"{HWAddresses.BROADCAST}", description="Broadcast")
        bc_s = bc_node.service_builders.get((self.transport, self.service_port))
        # Three entities:
        # host_s: ARP service at host
        # bc_node: Broadcast logical node
        # bc_s: ARP service a the broadcast node
        if not bc_s:
            # create ARP service
            bc_node.new_address_(HWAddresses.BROADCAST)
            bc_node.entity.external_activity = ExternalActivity.OPEN   # anyone can make broadcasts (it does not reply)
            bc_node.entity.host_type = HostType.ADMINISTRATIVE
            # ARP service at the broadcast node, but avoid looping back to ARPBackend
            bc_s = ARPBackend(ARP(), broadcast_endpoint=True).get_service_(bc_node)
            bc_s.entity.host_type = HostType.ADMINISTRATIVE
            bc_s.entity.con_type = ConnectionType.ADMINISTRATIVE
            bc_s.entity.external_activity = bc_node.entity.external_activity
            host_s.entity.external_activity = self.external_activity
        c_ok = any([c.source == host_s.entity for c in host_s.entity.get_parent_host().connections])
        if not c_ok:
            host_s >> bc_s
        return bc_s  # NOTE: the broadcast


class DHCPBackend(ProtocolBackend):
    def __init__(self, configurer: DHCP):
        super().__init__(Protocol.UDP, port=configurer.port, name="DHCP")
        # DHCP requests go to broadcast, thus the reply looks like request
        self.external_activity = ExternalActivity.UNLIMITED

    def _create_service(self, parent: HostBackend) -> ServiceBackend:
        host_s = ServiceBackend(parent, DHCPService(parent.entity))
        host_s.entity.external_activity = self.external_activity

        def create_source(host: HostBackend):
            # DHCP client uses specific port 68 for requests
            src = UDP(port=68, name="DHCP")
            src.port_to_name = False
            cs = host / src
            cs.entity.host_type = HostType.ADMINISTRATIVE
            cs.entity.con_type = ConnectionType.ADMINISTRATIVE
            cs.entity.client_side = True
            return cs
        host_s.source_fixer = create_source
        return host_s


class DNSBackend(ProtocolBackend):
    def __init__(self, configurer: DNS):
        super().__init__(Protocol.UDP, port=configurer.port, name="DNS")
        self.external_activity = ExternalActivity.OPEN
        self.captive_portal = configurer.captive

    def _create_service(self, parent: HostBackend) -> ServiceBackend:
        dns_s = DNSService(parent.entity)
        dns_s.captive_portal = self.captive_portal
        s = ServiceBackend(parent, dns_s)
        s.entity.external_activity = self.external_activity
        return s


class EAPOLBackend(ProtocolBackend):
    def __init__(self, configurer: EAPOL):
        super().__init__(Protocol.ETHERNET, port=0x888e, name=configurer.name)
        self.host_type = HostType.ADMINISTRATIVE
        self.con_type = ConnectionType.ADMINISTRATIVE
        self.external_activity = ExternalActivity.OPEN
        self.port_to_name = False


class HTTPBackend(ProtocolBackend):
    def __init__(self, configurer: HTTP):
        super().__init__(Protocol.TCP, port=configurer.port, protocol=Protocol.HTTP, name=configurer.name)
        self.authentication = configurer.auth
        self.redirect_only = False

    def get_service_(self, parent: HostBackend) -> ServiceBackend:
        s = super().get_service_(parent)
        if self.redirect_only:
            # persistent property
            s.entity.set_property(Properties.HTTP_REDIRECT.verdict(explanation="HTTP redirect to TLS"))
        return s


class ICMPBackend(ProtocolBackend):
    def __init__(self, configurer: ICMP):
        super().__init__(Protocol.IP, port=1, name=configurer.name)
        self.external_activity = ExternalActivity.OPEN
        self.port_to_name = False

    def _create_service(self, parent: HostBackend) -> ServiceBackend:
        s = super()._create_service(parent)
        s.entity.name = "ICMP"  # a bit of hack...
        s.entity.host_type = HostType.ADMINISTRATIVE
        s.entity.con_type = ConnectionType.ADMINISTRATIVE
        # ICMP can be a service for other hosts
        s.entity.external_activity = max(self.external_activity, parent.entity.external_activity)
        return s


class IPBackend(ProtocolBackend):
    def __init__(self, configurer: IP):
        super().__init__(Protocol.IP, name=configurer.name)
        if configurer.administration:
            self.host_type = HostType.ADMINISTRATIVE
            self.con_type = ConnectionType.ADMINISTRATIVE


class TLSBackend(ProtocolBackend):
    def __init__(self, configurer: TLS):
        super().__init__(Protocol.TCP, port=configurer.port, protocol=Protocol.TLS, name=configurer.name)
        self.authentication = configurer.auth
        self.con_type = ConnectionType.ENCRYPTED
        # self.critical_parameter.append(PieceOfData("TLS-creds"))


class NTPBackend(ProtocolBackend):
    def __init__(self, configurer: NTP):
        super().__init__(Protocol.UDP, port=configurer.port, name=configurer.name)
        self.host_type = HostType.ADMINISTRATIVE
        self.con_type = ConnectionType.ADMINISTRATIVE
        self.external_activity = ExternalActivity.OPEN


class SSHBackend(ProtocolBackend):
    def __init__(self, configurer: SSH):
        super().__init__(Protocol.TCP, port=configurer.port, protocol=Protocol.SSH, name=configurer.name)
        self.authentication = True
        self.con_type = ConnectionType.ENCRYPTED
        # self.critical_parameter.append(PieceOfData("SSH-creds"))


class TCPBackend(ProtocolBackend):
    def __init__(self, configurer: TCP):
        super().__init__(Protocol.TCP, port=configurer.port, name=configurer.name)
        if configurer.administrative:
            self.host_type = HostType.ADMINISTRATIVE
            self.con_type = ConnectionType.ADMINISTRATIVE


class UDPBackend(ProtocolBackend):
    def __init__(self, configurer: UDP):
        super().__init__(Protocol.UDP, port=configurer.port, name=configurer.name)
        if configurer.administrative:
            self.host_type = HostType.ADMINISTRATIVE
            self.con_type = ConnectionType.ADMINISTRATIVE

    def as_multicast_(self, address: str, system: SystemBackend) -> 'ServiceBackend':
        b = system.get_host_(address, description="Multicast")
        # Explicitly configured multicast nodes, at least are not administrative
        # b.entity.host_type = HostType.ADMINISTRATIVE
        addr = IPAddress.new(address)
        if addr not in b.entity.addresses:
            b.new_address_(addr)
        return self.get_service_(b)


class BLEAdvertisementBackend(ProtocolBackend):
    def __init__(self, configurer: BLEAdvertisement):
        super().__init__(Protocol.BLE, port=configurer.event_type, name=configurer.name, protocol=Protocol.BLE)

    def as_multicast_(self, address: str, system: SystemBackend) -> 'ServiceBackend':
        b = system.get_host_(name="BLE Ads", description="Bluetooth LE Advertisements")
        b.new_address_(Addresses.BLE_Ad)
        b.entity.external_activity = ExternalActivity.PASSIVE
        return self.get_service_(b)


class ProtocolConfigurers:
    """Protocol configurers and backends"""
    Constructors = {
        ARP: ARPBackend,
        DHCP: DHCPBackend,
        DNS: DNSBackend,
        EAPOL: EAPOLBackend,
        HTTP: HTTPBackend,
        ICMP: ICMPBackend,
        IP: IPBackend,
        TLS: TLSBackend,
        NTP: NTPBackend,
        SSH: SSHBackend,
        TCP: TCPBackend,
        UDP: UDPBackend,
        BLEAdvertisement: BLEAdvertisementBackend,
    }


class ClaimBackend(ClaimBuilder):
    """Claim builder"""
    def __init__(self, builder: 'ClaimSetBackend', explanation: str, verdict: Verdict, label: str,
                 authority=ClaimAuthority.MODEL):
        self.builder = builder
        self.authority = authority
        self.source = builder.sources.get(label)
        if self.source is None:
            builder.sources[label] = self.source = EvidenceSource(f"Claims '{label}'", label=label)
        self._explanation = explanation
        self._keys: List[PropertyKey] = []
        self._locations: List[Entity] = []
        self._verdict = verdict
        builder.claim_builders.append(self)

    def key(self, *segments: str) -> Self:
        key = PropertyKey.create(segments)
        if key.is_protected():
            key = key.prefix_key(Properties.PREFIX_MANUAL)
        self._keys.append(key)
        return self

    def keys(self, *key: Tuple[str, ...]) -> Self:
        for seg in key:
            assert isinstance(seg, tuple), f"Bad key {seg}"
            k = PropertyKey.create(seg)
            if k.is_protected():
                k = k.prefix_key(Properties.PREFIX_MANUAL)
            self._keys.append(k)
        return self

    def verdict_ignore(self) -> Self:
        self._verdict = Verdict.IGNORE
        return self

    def verdict_pass(self) -> Self:
        self._verdict = Verdict.PASS
        return self

    def at(self, *locations: Union[SystemBackend, NodeBackend, ConnectionBackend]) -> 'Self':
        for lo in locations:
            if isinstance(lo, SystemBackend):
                loc = lo.system
            elif isinstance(lo, NodeBackend):
                loc = lo.entity
            else:
                loc = lo.connection
            self._locations.append(loc)
        return self

    def software(self, *locations: NodeBackend) -> 'Self':
        for lo in locations:
            for sw in Software.list_software(lo.entity):
                self._locations.append(sw)
        return self

    def claims(self, *claims: Union[Claim, Tuple[str, str]]) -> Self:
        # bug? - requirements may be placed in extra tuple?
        cl = []
        for c in claims:
            if isinstance(c, tuple) and isinstance(c[0], Claim):
                cl.extend(c)
            else:
                cl.append(c)
        # self._claims.extend(cl)
        return self

    def vulnerabilities(self, *entry: Tuple[str, str]) -> Self:
        for com, cve in entry:
            self._keys.append(PropertyKey("vulnz", com, cve.lower()))
        return self

    ## Backend methods

    def finish_loaders(self) -> SubLoader:
        """Finish by returning the loader to use"""
        this = self
        locations = self._locations
        keys = self._keys

        class ClaimLoader(SubLoader):
            def __init__(self):
                super().__init__("Manual checks")
                self.source_label = this.source.label

            def load(self, registry: Registry, coverage: RequirementClaimMapper, filter: LabelFilter):
                if not filter.filter(self.source_label):
                    return
                evidence = Evidence(this.source)
                for loc in locations:
                    for key in keys:
                        kv = PropertyKey.create(key.segments).verdict(this._verdict, explanation=this._explanation)
                        ev = PropertyEvent(evidence, loc, kv)
                        registry.property_update(ev)
        return ClaimLoader()


class ClaimSetBackend(ClaimSetBuilder):
    """Builder for set of claims"""
    def __init__(self, builder: SystemBackend):
        self.builder = builder
        self.claim_builders: List[ClaimBackend] = []
        self.tool_plans: List[ToolPlanLoader] = []
        self.base_label = "explain"
        self.sources: Dict[str, EvidenceSource] = {}

    def set_base_label(self, base_label: str) -> Self:
        self.base_label = base_label
        return self

    def claim(self, explanation: str, verdict=Verdict.PASS) -> ClaimBackend:
        return ClaimBackend(self, explanation, verdict, self.base_label)

    def reviewed(self, explanation="", verdict=Verdict.PASS) -> ClaimBackend:
        return ClaimBackend(self, explanation, verdict, self.base_label, ClaimAuthority.MANUAL)

    def ignore(self, explanation="") -> ClaimBackend:
        return ClaimBackend(self, explanation, Verdict.IGNORE, self.base_label)

    def plan_tool(self, tool_name: str, group: Tuple[str, str], location: RequirementSelector, 
                  *key: Tuple[str, ...]) -> ToolPlanLoader:
        sl = ToolPlanLoader(group)
        sl.location = location
        for k in key:
            pk = PropertyKey.create(k)
            pv = pk.verdict(Verdict.PASS, explanation=f"{tool_name} sets {pk}")
            sl.properties[pk] = pv[1]
        self.tool_plans.append(sl)
        return sl

    ## Backend methods

    def finish_loaders(self) -> List[SubLoader]:
        """Finish"""
        ls = []
        ls.extend([cb.finish_loaders() for cb in self.claim_builders])
        ls.extend(self.tool_plans)
        return ls


if __name__ == "__main__":
    Builder.new().run()
