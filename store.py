"""
XVAY STORE — pluggable state backend so cross-step protection survives
multi-worker deployments. Decides nothing; it only persists.

Default: in-memory (single process, fastest).
Reference: FileStore — a real cross-process implementation with file locking,
proving the interface works. For production use Redis/DB by implementing the
same three methods: get(key) -> dict|None, put(key, dict), keys() -> list.
"""
import json, os, threading

class MemoryStore:
    def __init__(self): self._d = {}; self._lock = threading.Lock()
    def get(self, key):
        with self._lock: return self._d.get(key)
    def put(self, key, value):
        with self._lock: self._d[key] = value
    def delete(self, key):
        with self._lock: self._d.pop(key, None)
    def keys(self):
        with self._lock: return list(self._d.keys())
    def clear(self):
        with self._lock: self._d.clear()
    def update(self, key, fn):
        """ATOMIC read-modify-write. Required: get()+put() is a race."""
        with self._lock:
            nv = fn(self._d.get(key)); self._d[key] = nv; return nv

class FileStore:
    """Cross-process store. Every op takes an exclusive lock on the file, so two
    workers can safely share one run's trace. Reference implementation."""
    def __init__(self, path):
        self.path = path; self.lock = path + ".lock"; open(path, "a").close()
    def _acquire(self, timeout=30.0):
        """Portable exclusive lock (Windows + POSIX): atomic O_EXCL lock file.
        NOTE: when the lock file already exists, POSIX raises FileExistsError but
        WINDOWS raises PermissionError (EACCES). Both mean 'held' -> retry."""
        import time, errno
        start = time.time()
        while True:
            try:
                fd = os.open(self.lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                os.close(fd); return
            except (FileExistsError, PermissionError):
                pass
            except OSError as e:
                if e.errno not in (errno.EEXIST, errno.EACCES): raise
            if time.time() - start > timeout:        # stale lock from a dead process
                try: os.unlink(self.lock)
                except OSError: pass
                start = time.time()
            time.sleep(0.005)
    def _release(self):
        try: os.unlink(self.lock)
        except OSError: pass
    def _rw(self, fn):
        self._acquire()
        try:
            with open(self.path, "r+") as f:
                raw = f.read().strip()
                data = json.loads(raw) if raw else {}
                out = fn(data)
                f.seek(0); f.truncate(); f.write(json.dumps(data)); f.flush()
                os.fsync(f.fileno())
                return out
        finally:
            self._release()
    def get(self, key):   return self._rw(lambda d: d.get(key))
    def put(self, key, v):       self._rw(lambda d: d.__setitem__(key, v))
    def delete(self, key):       self._rw(lambda d: d.pop(key, None))
    def keys(self):       return self._rw(lambda d: list(d.keys()))
    def clear(self):             self._rw(lambda d: d.clear())
    def update(self, key, fn):
        """ATOMIC read-modify-write inside ONE file lock."""
        def _op(d):
            nv = fn(d.get(key)); d[key] = nv; return nv
        return self._rw(_op)

_STORE = MemoryStore()

def use(store):
    """Swap the backend once at startup: store.use(FileStore('/shared/xvay.json'))"""
    global _STORE; _STORE = store

def current(): return _STORE
