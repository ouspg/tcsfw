from ast import Set
import json
import logging
import pathlib
import io
from typing import Dict, Optional
from framing.raw_data import Raw
from tcsfw.event_interface import EventInterface
from tcsfw.model import EvidenceNetworkSource
from tcsfw.pcap_reader import PCAPReader
from tcsfw.traffic import IPFlow
from enum import StrEnum


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
            meta_file = file / "00meta.json"
            if meta_file.is_file():
                # the directory has data files
                if meta_file.stat().st_size == 0:
                    info = FileMetaInfo() # meta_file is empty
                else:
                    try:
                        with meta_file.open("rb") as f:
                            info = FileMetaInfo.parse_from_stream(f)
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

            # recursively scan the directory
            for child in proc_list:
                if info and child.is_file():
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
        try:
            if file_name.lower().endswith(".json") and info.file_type == BatchFileType.CAPTURE:
                # read flows from json
                return self._process_pcap_json(stream)

            if file_name.lower().endswith(".pcap") and info.file_type in {BatchFileType.UNSPECIFIED, BatchFileType.CAPTURE}:
                # read flows from pcap
                reader = PCAPReader(self.interface.get_system(), file_name)
                reader.source = info.source
                reader.interface = self.interface
                raw = Raw.stream(stream, name=file_name, request_size=1 << 20)
                return reader.parse(raw)
        except Exception as e:
            raise ValueError(f"Error in {file_name}") from e

        raise ValueError(f"Unsupported file '{file_name}' and type {info.file_type}")

    def _process_pcap_json(self, stream: io.BytesIO):
        """Read traffic from json"""
        json_data = json.load(stream)
        for fl in json_data.get("flows", []):
            flow = IPFlow.parse_from_json(fl)
            self.interface.connection(flow)


class BatchFileType(StrEnum):
    """Batch file type"""
    UNSPECIFIED = "unspecified"
    CAPTURE = "capture"

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

    @classmethod
    def parse_from_stream(cls, stream: io.BytesIO) -> 'FileMetaInfo':
        """Parse from stream"""
        return cls.parse_from_json(json.load(stream))

    @classmethod
    def parse_from_json(cls, json: Dict) -> 'FileMetaInfo':
        """Parse from JSON"""
        label = str(json.get("label", ""))
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