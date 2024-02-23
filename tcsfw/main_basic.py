from typing import Dict, Optional, Self, List

from tcsfw.address import AnyAddress, HWAddress, IPAddress
from tcsfw.batch_import import LabelFilter
from tcsfw.claim_coverage import RequirementClaimMapper
from tcsfw.components import Software
from tcsfw.model import ExternalActivity, EvidenceNetworkSource, Addressable, IoTSystem, Host
from tcsfw.registry import Registry


class BuilderInterface:
    """Abstract builder interface"""
    pass


class SystemInterface(BuilderInterface):
    """System root builder interface"""
    def __init__(self, name: str):
        self.system = IoTSystem(name)


class NodeInterface(BuilderInterface):
    """Node building interface"""
    def __init__(self, entity: Addressable, system: SystemInterface):
        self.entity = entity
        self.system = system

    def get_software(self) -> Software:
        raise NotImplementedError()


class HostInterface(NodeInterface):
    def __init__(self, entity: Host, system: SystemInterface):
        super().__init__(entity, system)
        self.entity = entity


class SoftwareInterface:
    """Software building interface"""
    def get_software(self) -> Software:
        raise NotImplementedError()
