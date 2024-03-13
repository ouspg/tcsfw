from tcsfw.entity_database import EntityDatabase, InMemoryDatabase
from sqlalchemy import create_engine

class SQLDatabase(InMemoryDatabase):
    """Use SQL database for storage"""
    def __init__(self, db_uri: str):
        super().__init__()
        self.engine = create_engine(db_uri)
        self.db_conn = self.engine.connect()
