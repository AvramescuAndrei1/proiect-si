from sqlalchemy import Column, Integer, String, Float, ForeignKey
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()

class Algorithm(Base):
    __tablename__ = 'algorithms'
    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True)
    type = Column(String)

class KeyRecord(Base):
    __tablename__ = 'keys'
    id = Column(Integer, primary_key=True)
    value = Column(String)
    alg_id = Column(Integer, ForeignKey('algorithms.id'))

class FileRecord(Base):
    __tablename__ = 'files'
    id = Column(Integer, primary_key=True)
    name = Column(String)
    path = Column(String)
    hash_val = Column(String)
    status = Column(String)
    key_val = Column(String)
    alg_used = Column(String)

class PerformanceLog(Base):
    __tablename__ = 'performance_logs'
    id = Column(Integer, primary_key=True)
    file_id = Column(Integer, ForeignKey('files.id', ondelete='CASCADE'))
    alg_name = Column(String)
    framework = Column(String)
    op = Column(String)
    time_ms = Column(Float)
    mem_kb = Column(Float)