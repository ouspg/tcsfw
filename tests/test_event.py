from tcsfw.basics import Verdict
from tcsfw.builder_backend import SystemBackend
from tcsfw.event_interface import PropertyEvent
from tcsfw.property import PropertyKey
from tcsfw.traffic import Evidence, EvidenceSource


def test_property_event():
    sb = SystemBackend()
    dev0 = sb.device()
    src = EvidenceSource("Source A")

    entities = {
        dev0.entity: 1,
    }

    p = PropertyEvent(Evidence(src), dev0.entity, PropertyKey("prop-a").verdict(Verdict.PASS))
    assert p.get_data_json(entities.get) == {
        'entity': 1, 
        'key': 'prop-a', 
        'verdict': 'Pass'
    }
