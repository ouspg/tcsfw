from ast import Set
import json
import logging
import pathlib
import io
from typing import Dict, List, Optional
from framing.raw_data import Raw
from tcsfw.android_manifest_scan import AndroidManifestScan
from tcsfw.censys_scan import CensysScan
from tcsfw.event_interface import EventInterface
from tcsfw.har_scan import HARScan
from tcsfw.mitm_log_reader import MITMLogReader
from tcsfw.model import EvidenceNetworkSource
from tcsfw.nmap_scan import NMAPScan
from tcsfw.pcap_reader import PCAPReader
from tcsfw.releases import ReleaseReader
from tcsfw.spdx_reader import SPDXReader
from tcsfw.ssh_audit_scan import SSHAuditScan
from tcsfw.testsslsh_scan import TestSSLScan
from tcsfw.traffic import IPFlow
from enum import StrEnum
from tcsfw.tshark_reader import TSharkReader
from tcsfw.vulnerability_reader import VulnerabilityReader

from tcsfw.zed_reader import ZEDReader


class BatchImporter:
    """Batch importer for importing a batch of files from a directory."""
    def __init__(self, interface: EventInterface, filter: 'LabelFilter' = None):
        self.interface = interface
        self.filter = filter or LabelFilter()
        self.logger = logging.getLogger("batch_importer")

    def import_batch(self, file: pathlib.Path):
        """Import a batch of files from a directory or zip file recursively."""
        if file.is_file() and file.suffix.lower() == ".zip":
            raise NotImplementedError("Zip file import is not implemented yet.")
        elif file.is_dir:
            self._import_batch(file)
        else:
            raise ValueError(f"Expected directory or ZIP as : {file.as_posix()}")

    def _import_batch(self, file: pathlib.Path):
        """Import a batch of files from a directory or zip file recursively."""
        self.logger.info(f"scanning {file.as_posix()}")
        if file.is_dir():
            dir_name = file.name
            meta_file = file / "00meta.json"
            if meta_file.is_file():
                # the directory has data files
                if meta_file.stat().st_size == 0:
                    info = FileMetaInfo(dir_name) # meta_file is empty
                else:
                    try:
                        with meta_file.open("rb") as f:
                            info = FileMetaInfo.parse_from_stream(f, dir_name)
                    except Exception as e:
                        raise ValueError(f"Error in {meta_file.as_posix()}") from e
            else:
                info = FileMetaInfo()

            # list files/directories to process
            proc_list = []
            for child in file.iterdir():
                if child == meta_file:
                    continue
                prefix = child.name[:1]
                if prefix in {".", "_"}:
                    continue
                postfix = child.name[-1:]
                if postfix in {"~"}:
                    continue
                proc_list.append(child)

            # filter by label
            skip_processing = not self.filter.filter(info.label)

            if not info.process_individually():
                # some files are processed at once
                if skip_processing:
                    self.logger.info(f"skipping ({info.label}) data files")
                    return
                self._do_process_files(proc_list, info)

            # recursively scan the directory
            for child in proc_list:
                if info and child.is_file():
                    if not info.process_individually():
                        continue
                    if not info.default_include and info.label not in self.filter.included:
                        self.logger.debug(f"skipping (default=False) {child.as_posix()}")
                        continue # skip file if not explicitly included
                    if skip_processing:
                        self.logger.info(f"skipping ({info.label}) {child.as_posix()}")
                        continue
                    self.logger.info(f"processing ({info.label}) {child.as_posix()}")
                    with child.open("rb") as f:
                        self._do_process(f, child, info)
                else:
                    self._import_batch(child)

    def _do_process(self, stream: io.BytesIO, file_path: pathlib.Path, info: 'FileMetaInfo'):
        """Process the file as stream"""
        file_name = file_path.name
        file_ext = file_path.suffix.lower()
        try:
            if file_ext == ".json" and info.file_type == BatchFileType.CAPTURE:
                # read flows from json
                return self._process_pcap_json(stream)

            reader = None
            if file_ext == ".pcap" and info.file_type in {BatchFileType.UNSPECIFIED, BatchFileType.CAPTURE}:
                # read flows from pcap
                reader = PCAPReader(self.interface.get_system())
            elif file_ext == ".json" and info.file_type == BatchFileType.CAPTURE_JSON:
                # read flows from JSON pcap
                reader = TSharkReader(self.interface.get_system())
            elif file_ext == ".log" and info.file_type == BatchFileType.MITMPROXY:
                # read MITM from textual log
                reader = MITMLogReader(self.interface.get_system())
            elif file_ext == ".xml" and info.file_type == BatchFileType.NMAP:
                # read NMAP from xml
                reader = NMAPScan(self.interface.get_system())
            elif file_ext == ".json" and info.file_type == BatchFileType.ZAP:
                # read ZAP from json
                reader = ZEDReader(self.interface.get_system())

            if reader:
                return reader.read_stream(stream, file_name, self.interface, info.source)

        except Exception as e:
            raise ValueError(f"Error in {file_name}") from e
        self.logger.info(f"skipping unsupported '{file_name}' type {info.file_type}")

    def _do_process_files(self, files: List[pathlib.Path], info: 'FileMetaInfo'):
        """Process files"""
        if info.file_type == BatchFileType.APK:
            tool = AndroidManifestScan(self.interface.get_system())
        elif info.file_type == BatchFileType.HAR:
            tool = HARScan(self.interface.get_system())
        elif info.file_type == BatchFileType.TESTSSL:
            tool = TestSSLScan(self.interface.get_system())
        elif info.file_type == BatchFileType.RELEASES:
            tool = ReleaseReader(self.interface.get_system())
        elif info.file_type == BatchFileType.SPDX:
            tool = SPDXReader(self.interface.get_system())
        elif info.file_type == BatchFileType.SSH_AUDIT:
            tool = SSHAuditScan(self.interface.get_system())
        elif info.file_type == BatchFileType.CENSYS:
            tool = CensysScan(self.interface.get_system())
        elif info.file_type == BatchFileType.VULNERABILITIES:
            tool = VulnerabilityReader(self.interface.get_system())
        else:
            raise ValueError(f"Unsupported file type {info.file_type}")
        unmapped = set(tool.file_name_map.keys())
        for fn in files:
            if not fn.is_file():
                continue  # directories called later
            address = tool.file_name_map.get(fn.name)
            if address:
                self.logger.info(f"processing ({info.file_type}) {fn.as_posix()}")
                with fn.open("rb") as f:
                    tool.process_file(address, f, self.interface, info.source)
                unmapped.remove(fn.name)
            else:
                self.logger.debug(f"unknown file name {fn.as_posix()}")
        if unmapped:
            self.logger.debug(f"no files for {sorted(unmapped)}")

    def _process_pcap_json(self, stream: io.BytesIO):
        """Read traffic from json"""
        json_data = json.load(stream)
        for fl in json_data.get("flows", []):
            flow = IPFlow.parse_from_json(fl)
            self.interface.connection(flow)


class BatchFileType(StrEnum):
    """Batch file type"""
    UNSPECIFIED = "unspecified"
    APK = "apk"
    CAPTURE = "capture"
    CAPTURE_JSON = "capture-json"
    CENSYS = "censys"
    HAR = "har"
    MITMPROXY = "mitmproxy"
    NMAP = "nmap"
    RELEASES = "releases"  # Github format
    SPDX = "spdx"
    SSH_AUDIT = "ssh-audit"
    TESTSSL = "testssl"
    VULNERABILITIES = "vulnerabilities"  # BlackDuck csv output
    ZAP = "zap"  # ZED Attack Proxy

    @classmethod
    def parse(cls, value: Optional[str]):
        """Parse from string"""
        if not value:
            return cls.UNSPECIFIED
        for t in cls:
            if t.value == value:
                return t
        raise ValueError(f"Unknown batch file type: {value}")


class FileMetaInfo:
    """Batch file information."""
    def __init__(self, label="", file_type=BatchFileType.UNSPECIFIED):
        self.label = label
        self.file_type = file_type
        self.default_include = True
        self.source = EvidenceNetworkSource(file_type)

    def process_individually(self) -> bool:
        """Process each file individually?"""
        return self.file_type not in {
            BatchFileType.APK, BatchFileType.CENSYS, BatchFileType.HAR, 
            BatchFileType.RELEASES, BatchFileType.SPDX, BatchFileType.SSH_AUDIT,
            BatchFileType.TESTSSL, BatchFileType.VULNERABILITIES}

    @classmethod
    def parse_from_stream(cls, stream: io.BytesIO, directory_name: str) -> 'FileMetaInfo':
        """Parse from stream"""
        return cls.parse_from_json(json.load(stream), directory_name)

    @classmethod
    def parse_from_json(cls, json: Dict, directory_name: str) -> 'FileMetaInfo':
        """Parse from JSON"""
        label = str(json.get("label", directory_name))
        file_type = BatchFileType.parse(json.get("file_type"))
        r = cls(label, file_type)
        r.default_include = bool(json.get("include", True))
        r.source.name = str(json.get("source_name")) or r.source.name
        return r

    def __repr__(self) -> str:
        return f"file_type: {self.file_type}, label: {self.label}"


class LabelFilter:
    """Filter labels"""
    def __init__(self, label_specification="") -> None:
        """Initialize the filter"""
        self.explicit_include = True
        self.included: Set[str] = set()
        self.excluded: Set[str] = set()
        spec = label_specification.strip()
        if spec == "":
            self.explicit_include = False
            return  # all included
        for index, d in enumerate(spec.split(",")):
            remove = d.startswith("^")
            if remove:
                # remove label
                if index == 0:
                    self.explicit_include = False
                self.excluded.add(d[1:])
            else:
                # include label
                self.included.add(d)
        intersect = self.included.intersection(self.excluded)
        if intersect:
            raise ValueError(f"Labels in both included and excluded: {intersect}")

    def filter(self, label: str) -> bool:
        """Filter the label"""
        if self.explicit_include:
            return label in self.included
        return label not in self.excluded