from tcsfw.main import ARP, DHCP, TCP
from tcsfw.selector import Finder
from tests.test_model import Setup


def test_finder():
    su = Setup()
    dev1 = su.system.device().hw("1:0:0:0:0:1")
    dev2 = su.system.device().hw("1:0:0:0:0:2")
    dev3 = su.system.device("Doe Hot")
    c0 = dev1 >> dev3 / TCP(1234)

    sp = Finder.specify(dev1.entity)
    assert sp == {"address": "Device|tag"}
    f = Finder.find(su.system.system, sp)
    assert f == dev1.entity

    sp = Finder.specify((dev2 / DHCP).entity)
    assert sp == {"address": "Device_2|tag/udp:67"}  # Not optimal
    f = Finder.find(su.system.system, sp)
    assert f.long_name() == "Device 2 DHCP"

    f = Finder.find(su.system.system, {"address": "Doe_Hot|tag", "software": "Doe Hot SW"})
    assert f is None
    sw = dev3.software("Sw")
    f = Finder.find(su.system.system, {"address": "Doe_Hot|tag", "software": "Sw"})
    assert f == sw.sw

    sp = Finder.specify((dev2 / ARP).entity)
    # assert sp == {"address": "Device_2|tag/arp"}  # Totally bogus
