import json
from typing import Any, Optional, Dict

from tcsfw.entity_database import EntityDatabase
from sqlalchemy import Boolean, Column, Integer, String, create_engine, delete, select
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from tcsfw.event_interface import PropertyAddressEvent, PropertyEvent
from tcsfw.model import Addressable, IoTSystem, NetworkNode

from tcsfw.traffic import Event, EvidenceSource

Base = declarative_base()

class TableEntityID(Base):
    __tablename__ = 'entity_ids'
    id = Column(Integer, primary_key=True)
    name = Column(String)
    type = Column(String)


class TableEvidenceSource(Base):
    __tablename__ = 'sources'
    id = Column(Integer, primary_key=True)
    name = Column(String)
    label = Column(String)
    base_ref = Column(String)
    model = Column(Boolean)


class TableEvent(Base):
    __tablename__ = 'events'
    id = Column(Integer, primary_key=True)
    type = Column(String)
    source_id = Column(Integer)  # TableEvidenceSource
    tail_ref = Column(String)
    data = Column(String) # JSON


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
        # cache of evidence sources
        self.source_cache: Dict[EvidenceSource, int] = {}
        self.free_source_id = 0
        self.event_types = {
            "prop-ent": PropertyEvent,
            "prop-add": PropertyAddressEvent,
        }
        self.event_names = {c: n for n, c in self.event_types.items()}
        self._purge_model_events()
        self._fill_cache()

    def _fill_cache(self):
        """Fill entity cache from database"""
        with Session(self.engine) as ses:
            # assuming limited number of entities, read all IDs
            sel = select(TableEntityID)
            for ent_id in ses.execute(sel).yield_per(1000).scalars():
                self.id_cache[ent_id.id] = ent_id
                self.id_by_name[ent_id.name] = ent_id.id

            # find the largest used source id from database
            sel = select(TableEvidenceSource)
            for src in ses.execute(sel).yield_per(1000).scalars():
                self.free_source_id = max(self.free_source_id, src.id)
            self.free_source_id += 1

    def _purge_model_events(self):
        """Purge model events from the database"""
        with Session(self.engine) as ses:
            # collect source_ids of model sources
            ids = set()
            sel = select(TableEvidenceSource.id).where(TableEvidenceSource.model == True)
            ids.update(ses.execute(sel).scalars())
            # select evets with these sources and delete them
            dele = delete(TableEvent).where(TableEvent.source_id.in_(ids))
            ses.execute(dele)
            ses.commit()
            # finally, delete the sources
            dele = delete(TableEvidenceSource).where(TableEvidenceSource.model == True)
            ses.execute(dele)
            ses.commit()


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
            with Session(self.engine) as ses:
                ent_id = TableEntityID(id=id_i, name=ent_name, type=entity.concept_name)
                ses.add(ent_id)
                ses.commit()
        else:
            # not stored to database
            id_i = self._cache_entity(entity)
        return id_i

    def _cache_entity(self, entity: Any) -> int:
        id_i = self.free_cache_id
        while id_i in self.id_cache:
            id_i += 1
        self.id_cache[entity] = self.free_cache_id = id_i
        self.free_cache_id += 1
        return id_i

    def get_entity(self, id_value: int) -> Optional[Any]:
        return self.id_cache.get(id_value)

    def put_event(self, event: Event):
        # store event to database
        # FIXME: Slow, should use bulk insert
        type_s = self.event_names.get(type(event))
        if type_s is None:
            return
        source = event.evidence.source
        source_id = self.source_cache.get(source, -1)
        with Session(self.engine) as ses:
            # Sources not restored from database, copies appear
            if source_id < 0:
                source_id = self.free_source_id
                self.free_source_id += 1
                src = TableEvidenceSource(id=source_id, name=source.name, label=source.label, base_ref=source.base_ref,
                                          model=source.model_override)
                ses.add(src)
                self.source_cache[source] = source_id
            js = event.get_data_json(self.get_id)
            ev = event.evidence
            ev = TableEvent(type=type_s, tail_ref=ev.tail_ref, source_id=source_id, data=json.dumps(js))
            ses.add(ev)
            ses.commit()