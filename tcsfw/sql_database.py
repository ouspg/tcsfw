from tcsfw.entity_database import EntityDatabase, InMemoryDatabase
from sqlalchemy import Column, Integer, String, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from tcsfw.model import NodeComponent

from tcsfw.traffic import Event

Base = declarative_base()

class TableEntityID(Base):
    __tablename__ = 'entity_id'
    id = Column(Integer, primary_key=True)
    name = Column(String)
    type = Column(String)

class SQLDatabase(InMemoryDatabase):
    """Use SQL database for storage"""
    def __init__(self, db_uri: str):
        super().__init__()
        self.engine = create_engine(db_uri)
        Base.metadata.create_all(self.engine)
        self.db_conn = self.engine.connect()

    def get_id(self, entity) -> int:
        id_i = super().get_id(entity)
        if isinstance(entity, NodeComponent):
            ses = sessionmaker(bind=self.engine)()
            ent_id = TableEntityID(id=id_i, name=entity.name, type=entity.concept_name)
            ses.add(ent_id)
            ses.commit()
            ses.close()
        return id_i
