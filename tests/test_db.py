import tempfile
from tcsfw.builder_backend import SystemBackend
from tcsfw.registry import Registry, Inspector
from tcsfw.sql_database import SQLDatabase


def test_db_id_storage():
    """Test storing and retrieving entity IDs from SQL database"""

    with tempfile.NamedTemporaryFile() as tmp_file:
        tmp = tmp_file.name

        # Run 1
        sb = SystemBackend()
        dev1 = sb.device()
        reg = Registry(Inspector(sb.system), db=SQLDatabase(f"sqlite:///{tmp}")).finish_model_load()
        assert reg.get_id(dev1.entity) == 2

        # Run 2
        sb = SystemBackend()
        dev2 = sb.device("Device two")
        reg = Registry(Inspector(sb.system), db=SQLDatabase(f"sqlite:///{tmp}")).finish_model_load()
        assert reg.get_id(dev2.entity) == 4

        # Run 3
        sb = SystemBackend()
        dev3 = sb.device("Device three")
        reg = Registry(Inspector(sb.system), db=SQLDatabase(f"sqlite:///{tmp}")).finish_model_load()
        assert reg.get_id(dev1.entity) == 2
        assert reg.get_id(dev3.entity) == 6
        assert reg.get_id(dev2.entity) == 4

