from typing import Any, Optional, Dict
from tcsfw.entity_database import EntityDatabase
from sqlalchemy import Column, Integer, String, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from tcsfw.model import Addressable, IoTSystem, NetworkNode

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
        self.free_cache_id = 1
        self.id_by_name: Dict[str, int] = {}
        self._fill_cache()

    def _fill_cache(self):
        """Fill cache from database"""
        ses = sessionmaker(bind=self.engine)()
        for ent_id in ses.query(TableEntityID):
            self.id_cache[ent_id.id] = ent_id
            self.free_cache_id = max(self.free_cache_id, ent_id.id + 1)
            # assuming limited number of entities, read all into memory
            self.id_by_name[ent_id.name] = ent_id.id
        ses.close()

    def finish_model_load(self, system: IoTSystem):
        """Put all entities into database"""
        for e in system.iterate_all():
            self.get_id(e)

    def reset(self, source_filter: Dict[str, bool] = None):
        pass

    def next_pending(self) -> Optional[Event]:
        return None

    def get_id(self, entity) -> int:
        id_i = self.id_cache.get(entity, -1)
        if id_i >= 0:
            return id_i
        if isinstance(entity, Addressable):
            ent_name = entity.long_name()  # for now, using long name
            id_i = self.id_by_name.get(ent_name, -1)
            if id_i >= 0:
                self.id_cache[entity] = id_i
                return id_i
            id_i = self._cache_entity(entity)
            self.id_by_name[ent_name] = id_i
            # store in database
            ses = sessionmaker(bind=self.engine)()
            ent_id = TableEntityID(id=id_i, name=ent_name, type=entity.concept_name)
            ses.add(ent_id)
            ses.commit()
            ses.close()
        else:
            # not stored to database
            id_i = self._cache_entity(entity)
        return id_i

    def _cache_entity(self, entity: Any) -> int:
        id_i = self.free_cache_id
        self.free_cache_id += 1
        self.id_cache[entity] = id_i
        return id_i

    def get_entity(self, id_value: int) -> Optional[Any]:
        return self.id_cache.get(id_value)

    def put_event(self, event: Event):
        pass # FIXME: implement this
