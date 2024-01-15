import pathlib
from tcsfw.batch_import import BatchImporter
from tcsfw.inspector import Inspector
from tcsfw.matcher import SystemMatcher
from tests.test_model import simple_setup_1


def test_import_batch_a():
    sb = simple_setup_1()
    im = BatchImporter(Inspector(sb.system))
    im.import_batch(pathlib.Path("tests/samples/batch/batch-a"))
    conn = sb.system.get_connections()
    assert len(conn) == 2


