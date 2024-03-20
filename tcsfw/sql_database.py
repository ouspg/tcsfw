import json
from typing import Any, Iterator, Optional, Dict, Tuple

from tcsfw.entity_database import EntityDatabase
from sqlalchemy import Boolean, Column, Integer, String, create_engine, delete, select
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from tcsfw.event_interface import EventInterface, PropertyAddressEvent, PropertyEvent
from tcsfw.model import Addressable, Connection, EvidenceNetworkSource, IoTSystem, NetworkNode, NodeComponent, Service
from tcsfw.services import NameEvent

from tcsfw.traffic import BLEAdvertisementFlow, EthernetFlow, Event, Evidence, EvidenceSource, HostScan, IPFlow, ServiceScan

Base = declarative_base()

class TableEntityID(Base):
    __tablename__ = 'entity_ids'
    id = Column(Integer, primary_key=True)
    name = Column(String)
    source = Column(Integer)    # optional
    target = Column(Integer)    # optional
    long_name = Column(String)  # null, if same as short name
    type = Column(String)


class TableEvidenceSource(Base):
    __tablename__ = 'sources'
    id = Column(Integer, primary_key=True)
    name = Column(String)
    label = Column(String)
    base_ref = Column(String)
    model = Column(Boolean)
    data = Column(String)  # JSON


class TableEvent(Base):
    __tablename__ = 'events'
    id = Column(Integer, primary_key=True)
    type = Column(String)
    source_id = Column(Integer)  # TableEvidenceSource
    tail_ref = Column(String)
    data = Column(String)  # JSON


class SQLDatabase(EntityDatabase):
    """Use SQL database for storage"""
    def __init__(self, db_uri: str):
        super().__init__()
        self.engine = create_engine(db_uri)
        Base.metadata.create_all(self.engine)
        self.db_conn = self.engine.connect()
        # cache of entity IDs
        self.id_by_key: Dict[Any, int] = {}      # Id by entity-type specific key
        self.id_cache: Dict[Any, int] = {}       # Id by entity
        self.entity_cache: Dict[int, Any] = {}   # Entity by id
        self.free_cache_id = 1
        # cache of evidence sources
        self.source_cache: Dict[EvidenceSource, int] = {}
        self.free_source_id = 0
        self.event_types = {
            "flow-eth": EthernetFlow,
            "flow-ip": IPFlow,
            "flow-ble": BLEAdvertisementFlow,
            "prop-ent": PropertyEvent,
            "prop-add": PropertyAddressEvent,
            "name": NameEvent,
            "scan-service": ServiceScan,
            "scan-host": HostScan,
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
                if ent_id.source is None and ent_id.target is None:
                    cache_key = ent_id.name  # host
                elif ent_id.source is not None and ent_id.target is not None:
                    cache_key = ent_id.source, ent_id.target  # component or connection
                elif ent_id.source is not None:
                    cache_key = ent_id.name, ent_id.source  # service
                else:
                    raise ValueError(f"Bad entity id row {ent_id}")
                self.id_by_key[cache_key] = ent_id.id
                self.entity_cache[ent_id.id] = None  # reserve ID
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

    def restore_stored(self, interface: EventInterface) -> Iterator[Event]:
        # Put all entities from model into the database
        system = interface.get_system()
        for e in system.iterate_all():
            self.get_id(e)
        # Read all events from database
        return self.read_events(interface)

    def read_events(self, interface: EventInterface) -> Iterator[Event]:
        """Real all events from database"""
        source_cache: Dict[int, EvidenceSource] = {}

        def get_source(source_id: int) -> EvidenceSource:
            src = source_cache.get(source_id)
            if src is None:
                with Session(self.engine) as ses:
                    sel = select(TableEvidenceSource).where(TableEvidenceSource.id == source_id)
                    r_data = ses.execute(sel).first()[0]
                    src = EvidenceNetworkSource(r_data.name, r_data.label, r_data.base_ref)
                    js = json.loads(r_data.data)
                    src.decode_data_json(js, self.get_entity)
                    source_cache[source_id] = src
            return src

        with Session(self.engine) as ses:
            sel = select(TableEvent)
            for ev in ses.execute(sel).yield_per(1000).scalars():
                event_type = self.event_types.get(ev.type)
                if event_type is None:
                    continue
                src = get_source(ev.source_id)
                if src is None:
                    self.logger.warning(f"Event {ev.id} has unknown source {ev.source_id}")
                    continue
                evi = Evidence(src, ev.tail_ref)
                js = json.loads(ev.data)
                event = event_type.decode_data_json(evi, js, self.get_entity)
                if event is None:
                    continue
                yield event

    def reset(self, source_filter: Dict[str, bool] = None):
        pass

    def next_pending(self) -> Optional[Event]:
        return None

    def get_id(self, entity) -> int:
        id_i = self.id_cache.get(entity, -1)
        if id_i >= 0:
            return id_i
        cache_key = None
        short_name = None
        long_name = None
        source_i = target_i = None
        if isinstance(entity, Service):
            # service
            source_i = self.get_id(entity.get_parent_host())
            short_name = entity.name
            long_name = entity.long_name()
            cache_key = short_name, source_i
        elif isinstance(entity, Addressable):
            # host or component
            short_name = entity.long_name()  # for now, using long name
            cache_key = short_name
        elif isinstance(entity, NodeComponent):
            # component
            short_name = entity.name
            source_i = self.get_id(entity.entity)
            cache_key = short_name, source_i
        elif isinstance(entity, Connection):
            # connection
            short_name = entity.long_name()
            source_i = self.get_id(entity.source)
            target_i = self.get_id(entity.target)
            cache_key = source_i, target_i

        if cache_key is not None:
            # store to DB, unless already stored
            id_i = self.id_by_key.get(cache_key, -1)
            if id_i >= 0:
                self.id_cache[entity] = id_i
                self.entity_cache[id_i] = entity
                return id_i
            id_i = self._cache_entity(entity)
            # store in database
            with Session(self.engine) as ses:
                ent_id = TableEntityID(id=id_i, name=short_name, source=source_i, target=target_i,
                                       long_name=long_name, type=entity.concept_name)
                ses.add(ent_id)
                ses.commit()
            self.id_by_key[cache_key] = id_i
        else:
            # not stored to database
            id_i = self._cache_entity(entity)
        return id_i

    def _cache_entity(self, entity: Any) -> int:
        id_i = self.free_cache_id
        while id_i in self.entity_cache:
            id_i += 1
        self.id_cache[entity] = self.free_cache_id = id_i
        self.entity_cache[id_i] = entity
        self.free_cache_id += 1
        return id_i

    def get_entity(self, id_value: int) -> Optional[Any]:
        return self.entity_cache.get(id_value)

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
                data_js = source.get_data_json(self.get_id)
                src = TableEvidenceSource(id=source_id, name=source.name, label=source.label, base_ref=source.base_ref,
                                          model=source.model_override, data=json.dumps(data_js))
                ses.add(src)
                self.source_cache[source] = source_id
            js = event.get_data_json(self.get_id)
            ev = event.evidence
            ev = TableEvent(type=type_s, tail_ref=ev.tail_ref, source_id=source_id, data=json.dumps(js))
            ses.add(ev)
            ses.commit()
