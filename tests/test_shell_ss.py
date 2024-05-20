"""Test shell command output parsing"""

import pathlib

from tcsfw.batch_import import BatchImporter
from tcsfw.components import OperatingSystem
from tcsfw.property import PropertyKey
from tcsfw.verdict import Verdict
from tests.test_model import Setup


class Setup_1(Setup):
    """Setup for tests here"""
    def __init__(self):
        super().__init__()
        self.device1 = self.system.device().hw("1:0:0:0:0:1")


def test_shell_ss_pass():
    su = Setup_1()
    BatchImporter(su.get_inspector()).import_batch(pathlib.Path("tests/samples/shell-ss"))
