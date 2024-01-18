import test_model
from tcsfw.address import EndpointAddress, Protocol, IPAddress
from tcsfw.inspector import Inspector
from tcsfw.main import SystemBuilder, UDP, TCP, UNLIMITED
from tcsfw.traffic import IPFlow, Evidence, EvidenceSource, ServiceScan, HostScan
from tcsfw.verdict import Status, Verdict


def simple_setup_3(tcp=False) -> SystemBuilder:
    sb = SystemBuilder()
    dev1 = sb.device().hw("1:0:0:0:0:1")
    dev2 = sb.device().ip("192.168.0.2")
    dev3 = sb.device().ip("192.168.0.3")
    if tcp:
        dev1 >> dev2 / TCP(port=1234)
    else:
        dev1 >> dev2 / UDP(port=1234)
    return sb


def test_traffic_verdict():
    sb = simple_setup_3()
    i = Inspector(sb.system)
    dev1 = sb.device("Device 1")
    dev2 = sb.device("Device 2")
    dev3 = sb.device("Device 3")

    assert all(d.entity.status_verdict() == (Status.EXPECTED, Verdict.UNDEFINED) for d in [dev1, dev2, dev3])

    # expected connections
    cs = i.connection(IPFlow.UDP("1:0:0:0:0:1", "192.168.0.1", 1100) >> ("1:0:0:0:0:2", "192.168.0.2", 1234))
    assert cs.status_verdict() == (Status.EXPECTED, Verdict.PASS)
    assert cs.target.status_verdict() == (Status.EXPECTED, Verdict.UNDEFINED)
    assert dev1.entity.status_verdict() == (Status.EXPECTED, Verdict.PASS)
    assert dev2.entity.status_verdict() == (Status.EXPECTED, Verdict.UNDEFINED)
    assert dev3.entity.status_verdict() == (Status.EXPECTED, Verdict.UNDEFINED)

    cs = i.connection(IPFlow.UDP("1:0:0:0:0:1", "192.168.0.1", 1100) << ("1:0:0:0:0:2", "192.168.0.2", 1234))
    assert cs.status_verdict() == (Status.EXPECTED, Verdict.PASS)
    assert cs.target.status_verdict() == (Status.EXPECTED, Verdict.PASS)
    assert dev1.entity.status_verdict() == (Status.EXPECTED, Verdict.PASS)
    assert dev2.entity.status_verdict() == (Status.EXPECTED, Verdict.PASS)
    assert dev3.entity.status_verdict() == (Status.EXPECTED, Verdict.UNDEFINED)

    # connection from unexpected host
    cs = i.connection(IPFlow.UDP("1:0:0:0:0:3", "192.168.0.3", 1100) >> ("1:0:0:0:0:2", "192.168.0.2", 1234))
    assert cs.status_verdict() == (Status.UNEXPECTED, Verdict.FAIL)
    assert dev1.entity.status_verdict() == (Status.EXPECTED, Verdict.PASS)
    assert dev2.entity.status_verdict() == (Status.EXPECTED, Verdict.PASS)
    assert dev3.entity.status_verdict() == (Status.EXPECTED, Verdict.PASS)

    # connection to unexpected host
    cs = i.connection(IPFlow.UDP("1:0:0:0:0:4", "192.168.0.4", 1100) << ("1:0:0:0:0:1", "192.168.0.1", 1234))
    assert cs.status_verdict() == (Status.UNEXPECTED, Verdict.FAIL)
    assert cs.target.status_verdict() == (Status.UNEXPECTED, Verdict.UNDEFINED)
    assert dev1.entity.status_verdict() == (Status.EXPECTED, Verdict.PASS)

    # unexpected service in known host
    cs = i.connection(IPFlow.UDP("1:0:0:0:0:3", "192.168.0.3", 1100) << ("1:0:0:0:0:2", "192.168.0.2", 1234))
    assert cs.status_verdict() == (Status.UNEXPECTED, Verdict.FAIL)
    assert dev2.entity.status_verdict() == (Status.EXPECTED, Verdict.PASS)
    assert dev3.entity.status_verdict() == (Status.EXPECTED, Verdict.PASS)


def test_irrelevant_traffic():
    sb = SystemBuilder()
    dev1 = sb.device().hw("1:0:0:0:0:1")
    dev2 = sb.device().ip("192.168.0.2")
    dev2.external_activity(UNLIMITED)
    dev1 >> dev2 / UDP(port=1234)
    i = Inspector(sb.system)

    # expected connections
    cs = i.connection(IPFlow.UDP("1:0:0:0:0:1", "192.168.0.1", 1100) >> ("1:0:0:0:0:2", "192.168.0.2", 1234))
    assert cs.status_verdict() == (Status.EXPECTED, Verdict.PASS)
    assert dev1.entity.status_verdict() == (Status.EXPECTED, Verdict.PASS)
    assert dev2.entity.status_verdict() == (Status.EXPECTED, Verdict.UNDEFINED)
    cs = i.connection(IPFlow.UDP("1:0:0:0:0:1", "192.168.0.1", 1100) << ("1:0:0:0:0:2", "192.168.0.2", 1234))
    assert cs.status_verdict() == (Status.EXPECTED, Verdict.PASS)
    assert dev1.entity.status_verdict() == (Status.EXPECTED, Verdict.PASS)
    assert dev2.entity.status_verdict() == (Status.EXPECTED, Verdict.PASS)

    # unexpected connection to known service
    cs = i.connection(IPFlow.UDP("1:0:0:0:0:3", "192.168.0.3", 1100) >> ("1:0:0:0:0:2", "192.168.0.2", 1234))
    dev3 = cs.source
    assert cs.status_verdict() == (Status.EXTERNAL, Verdict.UNDEFINED)
    assert dev1.entity.status_verdict() == (Status.EXPECTED, Verdict.PASS)  
    assert dev3.status_verdict() == (Status.EXTERNAL, Verdict.UNDEFINED)

    # connection to unexpected service
    cs = i.connection(IPFlow.UDP("1:0:0:0:0:2", "192.168.0.2", 1100) >> ("1:0:0:0:0:4", "192.168.0.4", 4444))
    dev4 = cs.target
    assert cs.status_verdict() == (Status.EXTERNAL, Verdict.UNDEFINED)
    assert dev2.entity.status_verdict() == (Status.EXPECTED, Verdict.PASS)
    assert dev3.status_verdict() == (Status.EXTERNAL, Verdict.UNDEFINED)


def test_scan():
    sb = simple_setup_3(tcp=True)
    i = Inspector(sb.system)

    ev = Evidence(EvidenceSource(""))

    s1 = i.service_scan(ServiceScan(ev, EndpointAddress.ip("192.168.0.2", Protocol.TCP, 1234)))
    assert s1.status_verdict() == (Status.EXPECTED, Verdict.PASS)
    assert s1.get_parent_host().status_verdict() == (Status.EXPECTED, Verdict.PASS)

    s2 = i.service_scan(ServiceScan(ev, EndpointAddress.ip("192.168.0.2", Protocol.TCP, 2234)))
    assert s2.status_verdict() == (Status.UNEXPECTED, Verdict.FAIL)
    assert s2.get_parent_host().status_verdict() == (Status.EXPECTED, Verdict.PASS)

    hs = i.host_scan(HostScan(ev, IPAddress.new("192.168.0.2"), set()))
    assert hs.status_verdict() == (Status.EXPECTED, Verdict.PASS)
    assert s1.status_verdict() == (Status.EXPECTED, Verdict.FAIL)
    assert hs == s1.get_parent_host()
    assert hs == s2.get_parent_host()


def test_foreign_connection():
    sb = test_model.simple_setup_1()
    dev2 = sb.system.get_endpoint(IPAddress.new("192.168.0.2"))
    dev2.set_external_activity(UNLIMITED)
    i = Inspector(sb.system)

    # target is known service
    cs1 = i.connection(IPFlow.UDP(
        "20:0:0:0:0:1", "192.168.10.1", 2000) >> ("1:0:0:0:0:2", "192.168.0.2", 1234))
    cs1_2 = i.connection(IPFlow.UDP(
        "20:0:0:0:0:1", "192.168.10.1", 2000) << ("1:0:0:0:0:2", "192.168.0.2", 1234))
    assert cs1 == cs1_2
    assert cs1.status.verdict == Verdict.EXTERNAL
    assert cs1.source.status.verdict == Verdict.EXTERNAL
    assert cs1.source.get_parent_host().status.verdict == Verdict.EXTERNAL
    assert cs1.target.status.verdict == Verdict.PASS
    assert cs1.target.get_parent_host().status.verdict == Verdict.PASS

    # target is unknown service, fine for UNLIMITED activity
    cs2 = i.connection(IPFlow.UDP(
        "20:0:0:0:0:1", "192.168.10.1", 2000) >> ("1:0:0:0:0:2", "192.168.0.2", 2001))
    cs2_2 = i.connection(IPFlow.UDP(
        "20:0:0:0:0:1", "192.168.10.1", 2000) << ("1:0:0:0:0:2", "192.168.0.2", 2001))
    assert cs2 == cs2_2
    assert cs2.status.verdict == Verdict.EXTERNAL
    assert cs2.source.status.verdict == Verdict.EXTERNAL
    assert cs2.source.get_parent_host().status.verdict == Verdict.EXTERNAL
    assert cs2.target.status.verdict == Verdict.EXTERNAL
    assert cs2.target.get_parent_host().status.verdict == Verdict.PASS


def test_multicast():
    sb = SystemBuilder()
    dev1 = sb.device().hw("1:0:0:0:0:1")
    dev1 >> sb.broadcast(UDP(port=333))
    i = Inspector(sb.system)

    cs1 = i.connection(IPFlow.UDP(
        "1:0:0:0:0:1", "192.168.0.1", 1100) >> ("ff:ff:ff:ff:ff:ff", "255.255.255.255", 333))
    assert cs1.status.verdict == Verdict.PASS
    assert cs1.source.status.verdict == Verdict.PASS
    assert cs1.target.is_multicast()
    assert cs1.target.status.verdict == Verdict.PASS

    cs2 = i.connection(IPFlow.UDP(
        "1:0:0:0:0:1", "192.168.0.1", 1100) >> ("ff:ff:ff:ff:ff:ff", "255.255.255.255", 222))
    assert cs2.status.verdict == Verdict.UNEXPECTED
    assert cs2.source.status.verdict == Verdict.UNEXPECTED
    assert cs2.target.is_multicast()
    assert cs2.target.status.verdict == Verdict.UNEXPECTED
