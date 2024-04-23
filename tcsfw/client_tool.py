"""Clinet tool for TCSFW"""

import argparse
import json
import logging
import pathlib
import sys
from typing import BinaryIO, Dict, List
import tempfile
import zipfile

import requests

from tcsfw.batch_import import FileMetaInfo
from tcsfw.command_basics import get_api_key

class ClientTool:
    """Client tool"""
    def __init__(self) -> None:
        self.logger = logging.getLogger(__name__)
        self.auth_token = get_api_key()
        self.timeout = -1

    def run(self):
        """Run the client tool"""
        parser = argparse.ArgumentParser(prog="tcsfw", description="TCSFW client tool")
        parser.add_argument("-l", "--log", dest="log_level", choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                            help="Set the logging level", default=None)

        subparsers = parser.add_subparsers(title="commands", dest="command")
        subparsers.required = True
        # Subcommand: upload files
        upload_parser = subparsers.add_parser("upload", help="Upload tool output")
        upload_parser.add_argument("--read", "-r", help="Path to file or directory to upload, default stdin")
        upload_parser.add_argument("--meta", "-m", help="Meta-data in JSON format")
        upload_parser.add_argument("--url", "-u", default="https://localhost:5173", help="Server URL")
        upload_parser.add_argument("--timeout", type=int, default=300, help="Server timeout, default is 5 min")

        args = parser.parse_args()
        logging.basicConfig(format='%(message)s', level=getattr(
            logging, args.log_level or 'INFO'))

        # if args.command == 'upload':
        self.run_upload(args)

    def run_upload(self, args: argparse.Namespace):
        """Run upload subcommand"""
        meta_json = json.loads(args.meta) if args.meta else {}

        url = args.url
        self.timeout = args.timeout
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
            self.upload_file(url, sys.stdin.buffer, meta_json)
        self.logger.info("upload complete")

    def upload_file(self, url: str, file_data: BinaryIO, meta_json: Dict):
        """Upload a file"""
        # create a temporary zip file
        with tempfile.NamedTemporaryFile(suffix='.zip') as temp_file:
            self.create_zipfile(file_data, meta_json, temp_file)
            self.upload_file_data(url, temp_file)

    def upload_directory(self, url: str, path: pathlib.Path):
        """Upload directory"""
        files = sorted(path.iterdir())

        meta_file = path / "00meta.json"
        if meta_file.exists():
            with meta_file.open() as f:
                meta_json = json.load(f)
            file_load_order = meta_json.get("file_order", [])
            if file_load_order:
                # sort subdirectories based on file_load_order
                files = FileMetaInfo.sort_load_order(files, file_load_order)

            # meta file exists -> upload files from here
            self.logger.info("Uploading directory %s", path.as_posix())
            with tempfile.NamedTemporaryFile(suffix='.zip') as temp_file:
                self.copy_to_zipfile(files, temp_file)
                self.upload_file_data(url, temp_file)

        # visit subdirectories
        for subdir in files:
            if subdir.is_dir():
                self.upload_directory(url, subdir)

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

    def copy_to_zipfile(self, files: List[pathlib.Path], temp_file: BinaryIO):
        """Copy files from directory into zipfile"""
        chunk_size = 256 * 1024
        with zipfile.ZipFile(temp_file.name, 'w') as zip_file:
            for file in files:
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
        else:
            self.logger.warning("No API key found for upload")
        resp = requests.post(full_url, data=temp_file, headers=headers, timeout=60)
        resp.raise_for_status()
        return resp

def main():
    """Main entry point"""
    ClientTool().run()

if __name__ == "__main__":
    ClientTool().run()
