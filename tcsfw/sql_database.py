from tcsfw.entity_database import EntityDatabase


class SQLDatabase(EntityDatabase):
    def __init__(self, db_uri: str):
        super().__init__()
        