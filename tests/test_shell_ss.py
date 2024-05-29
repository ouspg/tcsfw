"""Test shell command output parsing"""

import pathlib

from tcsfw.basics import ExternalActivity, Status
from tcsfw.batch_import import BatchImporter
from tcsfw.main import SSH
from tcsfw.verdict import Verdict
from tests.test_model import Setup


class Setup_1(Setup):
    """Setup for tests here"""
    def __init__(self):
        super().__init__()
        self.device1 = self.system.device().ip("65.21.253.97")
        self.ssh = self.device1 / SSH
        self.ssh.external_activity(ExternalActivity.PASSIVE)


def test_shell_ss_pass():
    su = Setup_1()
    BatchImporter(su.get_inspector()).import_batch(pathlib.Path("tests/samples/shell-ss"))
    hs = su.get_hosts()
    co = su.get_connections()
    assert len(hs) == 6
    h = hs[0]
    assert h.status_verdict() == (Status.EXPECTED, Verdict.PASS)
    assert len(h.children) == 6
    s = h.children[0]
    assert s.long_name() == "Device SSH:22"
    assert s.status_verdict() == (Status.EXPECTED, Verdict.PASS)
    s = h.children[1]
    assert s.long_name() == "Device TCP:51337"
    assert s.status_verdict() == (Status.UNEXPECTED, Verdict.FAIL)
    s = h.children[2]
    assert s.long_name() == "Device UDP:68"
    assert s.status_verdict() == (Status.UNEXPECTED, Verdict.FAIL)
    s = h.children[3]
    assert s.long_name() == "Device TCP:41337"
    assert s.status_verdict() == (Status.UNEXPECTED, Verdict.FAIL)
    s = h.children[4]
    assert s.long_name() == "Device UDP:1194"
    assert s.status_verdict() == (Status.UNEXPECTED, Verdict.FAIL)
    s = h.children[5]
    assert s.long_name() == "Device UDP:123"
    assert s.status_verdict() == (Status.UNEXPECTED, Verdict.FAIL)
