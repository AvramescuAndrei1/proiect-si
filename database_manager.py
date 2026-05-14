import hashlib
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import Base, Algorithm, FileRecord, PerformanceLog, KeyRecord

class DBManager:
    def __init__(self, db_name="crypto_vault.db"):
        self.engine = create_engine(f"sqlite:///{db_name}")
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)
        self._seed()

    def _seed(self):
        s = self.Session()
        if s.query(Algorithm).count() == 0:
            s.add_all([Algorithm(name="AES-256", type="Symmetric"), 
                       Algorithm(name="RSA-2048", type="Asymmetric")])
            s.commit()
        s.close()

    def get_hash(self, path):
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()

    def add_file(self, name, path, key_val, alg_name, status="Criptat"):
        s = self.Session()
        h = self.get_hash(path)
        f = FileRecord(name=name, path=path, hash_val=h, status=status, key_val=key_val, alg_used=alg_name)
        s.add(f)
        s.commit()
        fid = f.id
        s.close()
        return fid

    def add_log(self, fid, alg, fw, op, t, m):
        s = self.Session()
        log = PerformanceLog(file_id=fid, alg_name=alg, framework=fw, op=op, time_ms=t, mem_kb=m)
        s.add(log)
        s.commit()
        s.close()

    def get_files(self):
        s = self.Session()
        res = s.query(FileRecord).all()
        s.close()
        return res

    def get_file_details(self, fid):
        s = self.Session()
        f = s.query(FileRecord).filter_by(id=fid).first()
        log = s.query(PerformanceLog).filter_by(file_id=fid).order_by(PerformanceLog.id.desc()).first()
        if log:
            f.perf_t, f.perf_m, f.perf_fw = log.time_ms, log.mem_kb, log.framework
        else:
            f.perf_t, f.perf_m, f.perf_fw = "N/A", "N/A", "N/A"
        s.close()
        return f

    def save_key(self, val, alg_name):
        s = self.Session()
        if not s.query(KeyRecord).filter_by(value=val).first():
            s.add(KeyRecord(value=val))
            s.commit()
        s.close()

    def get_keys(self):
        s = self.Session()
        res = [k.value for k in s.query(KeyRecord).all()]
        s.close()
        return res