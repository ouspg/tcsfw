from tcsfw.address import Addresses
from tcsfw.basics import Verdict
from tcsfw.builder_backend import SystemBackend
from tcsfw.event_interface import PropertyAddressEvent, PropertyEvent
from tcsfw.property import PropertyKey
from tcsfw.traffic import Evidence, EvidenceSource


def test_property_event():
    sb = SystemBackend()
    dev0 = sb.device()
    evi = Evidence(EvidenceSource("Source A"))

    entities = {
        dev0.entity: 1,
    }
    ent_reverse = {v: k for k, v in entities.items()}

    p = PropertyEvent(evi, dev0.entity, PropertyKey("prop-a").verdict(Verdict.PASS))
    js = p.get_data_json(entities.get)
    assert js == {
        'entity': 1, 
        'key': 'prop-a', 
        'verdict': 'Pass'
    }

    p2 = PropertyEvent.decode_data_json(evi, js, ent_reverse.get)
    assert p2.get_verdict() == Verdict.PASS
    assert p == p2


def test_property_address_event():
    sb = SystemBackend()
    dev0 = sb.device()
    evi = Evidence(EvidenceSource("Source A"))

    p = PropertyAddressEvent(evi, Addresses.parse_address("1.2.3.4"), PropertyKey("prop-a").verdict(Verdict.FAIL))
    js = p.get_data_json(lambda x: None)
    assert js == {
        'address': "1.2.3.4",
        'key': 'prop-a',
        'verdict': 'Fail'
    }

    p2 = PropertyAddressEvent.decode_data_json(evi, js, lambda x: None)
    assert p2.get_verdict() == Verdict.FAIL
    assert p == p2
