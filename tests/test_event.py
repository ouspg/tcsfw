from tcsfw.basics import Verdict
from tcsfw.builder_backend import SystemBackend
from tcsfw.event_interface import PropertyEvent
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
    assert p == p2
