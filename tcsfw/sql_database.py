from typing import Any, Optional, Dict
from tcsfw.entity_database import EntityDatabase
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


class SQLDatabase(EntityDatabase):
    """Use SQL database for storage"""
    def __init__(self, db_uri: str):
        super().__init__()
        self.engine = create_engine(db_uri)
        Base.metadata.create_all(self.engine)
        self.db_conn = self.engine.connect()
        # cache of entity IDs
        self.id_cache: Dict[Any, int] = {}

    def reset(self, source_filter: Dict[str, bool] = None):
        pass

    def next_pending(self) -> Optional[Event]:
        return None

    def get_id(self, entity) -> int:
        id_i = self.id_cache.get(entity, -1)
        if id_i >= 0:
            return id_i
        id_i = len(self.id_cache) + 1  # start from 1
        self.id_cache[entity] = id_i
        if isinstance(entity, NodeComponent):
            ses = sessionmaker(bind=self.engine)()
            ent_id = TableEntityID(id=id_i, name=entity.name, type=entity.concept_name)
            ses.add(ent_id)
            ses.commit()
            ses.close()
        return id_i

    def get_entity(self, id_value: int) -> Optional[Any]:
        return self.id_cache.get(id_value)

    def put_event(self, event: Event):
        pass # FIXME: implement this
