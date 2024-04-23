"""Clinet tool for TCSFW"""

import argparse
from io import BytesIO
import json
import logging
import os
import pathlib
import sys
from typing import BinaryIO, Dict
import tempfile
import zipfile

import requests

class ClientTool:
    """Client tool"""
    def __init__(self) -> None:
        self.logger = logging.getLogger(__name__)

    def run(self):
        """Run the client tool"""
        parser = argparse.ArgumentParser(prog="client", description="TCSFW client tool")
        parser.add_argument("-l", "--log", dest="log_level", choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                            help="Set the logging level", default=None)

        subparsers = parser.add_subparsers(title="commands", dest="command")
        subparsers.required = True
        # Subcommand: upload files
        upload_parser = subparsers.add_parser("upload", help="Upload tool output")
        upload_parser.add_argument("--read", "-r", help="Path to file or directory to upload, default stdin")
        upload_parser.add_argument("--meta", "-m", help="Meta-data in JSON format")
        upload_parser.add_argument("--url", "-u", default="https://localhost:5173", help="Server URL")

        args = parser.parse_args()
        logging.basicConfig(format='%(message)s', level=getattr(
            logging, args.log_level or 'INFO'))

        self.auth_token = os.environ.get("TCSFW_SERVER_API_KEY", "")

        # if args.command == 'upload':
        self.run_upload(args)

    def run_upload(self, args: argparse.Namespace):
        """Run upload subcommand"""
        meta_json = json.loads(args.meta) if args.meta else {}

        url = args.url
        if args.read:
            read_file = pathlib.Path(args.read)
            if read_file.is_dir():
                # uploading data from directory with meta-files in place
                self.upload_directory(url, read_file)
            else:
                # uploading single file
                if not meta_json:
                    raise ValueError("Missing upload meta-data")
                self.logger.info("Uploading %s to %s...", read_file.as_posix(), url)
                with read_file.open('rb') as f:
                    self.upload_file(url, f, meta_json)

        else:
            # uploading from stdin
            if not meta_json:
                raise ValueError("Missing upload meta-data")
            self.logger.info("Uploading to %s...", url)
            self.upload_file(url, f, sys.stdin.buffer)
        self.logger.info("upload complete")

    def upload_file(self, url: str, file_data: BinaryIO, meta_json: Dict):
        """Upload a file"""
        # create a temporary zip file
        with tempfile.NamedTemporaryFile(suffix='.zip') as temp_file:
            self.create_zipfile(file_data, meta_json, temp_file)
            self.upload_file_data(url, temp_file)

    def upload_directory(self, url: str, path: pathlib.Path):
        """Upload directory"""
        if (path / "00meta.json").exists():
            # meta file exists -> upload files from here
            self.logger.info("Uploading directory %s", path.as_posix())
            with tempfile.NamedTemporaryFile(suffix='.zip') as temp_file:
                self.copy_to_zipfile(path, temp_file)
                self.upload_file_data(url, temp_file)

    def create_zipfile(self, file_data: BinaryIO, meta_json: Dict, temp_file: BinaryIO):
        """Create zip file"""
        chunk_size = 256 * 1024
        with zipfile.ZipFile(temp_file.name, 'w') as zip_file:
            # write meta-data
            zip_file.writestr("00meta.json", json.dumps(meta_json))
            # write content
            zip_info = zipfile.ZipInfo("data")
            with zip_file.open(zip_info, "w") as of:
                chunk = file_data.read(chunk_size)
                while chunk:
                    of.write(chunk)
                    chunk = file_data.read(chunk_size)
        temp_file.seek(0)

    def copy_to_zipfile(self, path: pathlib.Path, temp_file: BinaryIO):
        """Copy files from directory into zipfile"""
        chunk_size = 256 * 1024
        with zipfile.ZipFile(temp_file.name, 'w') as zip_file:
            for file in path.iterdir():
                if not file.is_file():
                    continue
                # write content
                zip_info = zipfile.ZipInfo(file.name)
                with file.open("rb") as file_data:
                    with zip_file.open(zip_info, "w") as of:
                        chunk = file_data.read(chunk_size)
                        while chunk:
                            of.write(chunk)
                            chunk = file_data.read(chunk_size)
        temp_file.seek(0)

    def upload_file_data(self, base_url: str, temp_file: BinaryIO):
        """Upload content zip file into the server"""
        full_url = f"{base_url}/api1/batch"
        headers = {
            "Content-Type": "application/zip",
        }
        if self.auth_token:
            headers["X-Authorization"] = self.auth_token
        resp = requests.post(full_url, data=temp_file, headers=headers, timeout=60)
        resp.raise_for_status()
        return resp

if __name__ == "__main__":
    ClientTool().run()
