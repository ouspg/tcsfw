"""Test shell command output parsing"""

import pathlib

from tcsfw.basics import Status
from tcsfw.batch_import import BatchImporter
from tcsfw.verdict import Verdict
from tests.test_model import Setup


class Setup_1(Setup):
    """Setup for tests here"""
    def __init__(self):
        super().__init__()
        self.device1 = self.system.device().ip("192.168.6.12")


def test_shell_ss_pass():
    su = Setup_1()
    BatchImporter(su.get_inspector()).import_batch(pathlib.Path("tests/samples/shell-ss"))
    hs = su.get_hosts()
    assert len(hs) == 3
    h = hs[0]
    assert len(h.children) == 4
    s = h.children[0]
    assert s.long_name() == "Device TCP:22"
    assert s.status_verdict() == (Status.UNEXPECTED, Verdict.FAIL)
    s = h.children[1]
    assert s.long_name() == "Device TCP:41337"
    assert s.status_verdict() == (Status.UNEXPECTED, Verdict.FAIL)
    s = h.children[2]
    assert s.long_name() == "Device UDP:1194"
    assert s.status_verdict() == (Status.UNEXPECTED, Verdict.FAIL)
    s = h.children[3]
    assert s.long_name() == "Device UDP:123"
    assert s.status_verdict() == (Status.UNEXPECTED, Verdict.FAIL)
