import json
import logging
import pathlib
import io
from typing import Dict
from framing.raw_data import Raw
from tcsfw.event_interface import EventInterface
from tcsfw.model import EvidenceNetworkSource
from tcsfw.pcap_reader import PCAPReader
from tcsfw.traffic import IPFlow


class BatchImporter:
    """Batch importer for importing a batch of files from a directory."""
    def __init__(self, interface: EventInterface):
        self.interface = interface
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
                    with meta_file.open("rb") as f:
                        info = FileMetaInfo.parse_from_stream(f)
            else:
                info = None
            # recursively scan the directory
            for child in file.iterdir():
                if info and child.is_file():
                    self.logger.info(f"processing {child.as_posix()}")
                    with child.open("rb") as f:
                        self._do_process(f, child.name, info)
                else:
                    self._import_batch(child)

    def _do_process(self, stream: io.BytesIO, file_name: str, info: 'FileMetaInfo'):
        """Process the file as stream"""
        if info.file_type == FileMetaInfo.CAPTURE and file_name.lower().endswith(".json"):
            # read flows from json
            return self._process_pcap_json(stream)

        if file_name.lower().endswith(".pcap"):
            # read flows from pcap
            reader = PCAPReader(self.interface.get_system(), file_name)
            reader.source = info.source
            reader.interface = self.interface
            return reader.parse(Raw.stream(stream, name=file_name))

        raise ValueError(f"Unsupported file '{file_name}' and type {info.file_type}")

    def _process_pcap_json(self, stream: io.BytesIO):
        """Read traffic from json"""
        json_data = json.load(stream)
        for fl in json_data.get("flows", []):
            flow = IPFlow.parse_from_json(fl)
            self.interface.connection(flow)


class FileMetaInfo:
    """Batch file information."""
    def __init__(self, file_type=None):
        self.file_type = self.UNSPECIFIED if file_type is None else file_type
        self.source = EvidenceNetworkSource(file_type)

    UNSPECIFIED = "unspecified"     # unspecified file type
    CAPTURE = "capture"             # traffic capture  

    @classmethod
    def parse_from_stream(cls, stream: io.BytesIO) -> 'FileMetaInfo':
        """Parse from stream"""
        return cls.parse_from_json(json.load(stream))

    @classmethod
    def parse_from_json(cls, json: Dict) -> 'FileMetaInfo':
        """Parse from JSON"""
        file_type = str(json.get("file_type")) or cls.UNSPECIFIED
        r = cls(file_type=file_type)
        r.source.name = str(json.get("source_name")) or r.source.name
        return r

    def __repr__(self) -> str:
        return f"file_type = {self.file_type}"