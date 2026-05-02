import time
from typing import Any, Callable


class CacheEntry:
    def __init__(self, value: Any, ttl: int):
        self.value      = value
        self.expires_at = time.time() + ttl

    def is_expired(self) -> bool:
        return time.time() > self.expires_at


class InMemoryCache:
    def __init__(self):
        self._store: dict[str, CacheEntry] = {}
        self._hits   = 0
        self._misses = 0

    def get(self, key: str) -> Any | None:
        entry = self._store.get(key)
        if entry is None or entry.is_expired():
            if entry:
                del self._store[key]
            self._misses += 1
            return None
        self._hits += 1
        return entry.value

    def set(self, key: str, value: Any, ttl: int = 300):
        self._store[key] = CacheEntry(value, ttl)

    def delete(self, key: str):
        self._store.pop(key, None)

    def clear(self):
        self._store.clear()

    def invalidate_prefix(self, prefix: str):
        keys = [k for k in self._store if k.startswith(prefix)]
        for k in keys:
            del self._store[k]

    def cleanup_expired(self):
        expired = [k for k, v in self._store.items() if v.is_expired()]
        for k in expired:
            del self._store[k]
        return len(expired)

    def stats(self) -> dict:
        self.cleanup_expired()
        total = self._hits + self._misses
        return {
            "size":      len(self._store),
            "hits":      self._hits,
            "misses":    self._misses,
            "hit_rate":  round(self._hits / total * 100, 1) if total else 0.0,
        }

    def cached(self, key: str, ttl: int = 300):
        def decorator(func: Callable):
            def wrapper(*args, **kwargs):
                cached_val = self.get(key)
                if cached_val is not None:
                    return cached_val
                result = func(*args, **kwargs)
                self.set(key, result, ttl)
                return result
            return wrapper
        return decorator


_cache = InMemoryCache()


def get_cache() -> InMemoryCache:
    return _cache


def cached(key: str, ttl: int = 300):
    def decorator(func: Callable):
        def wrapper(*args, **kwargs):
            full_key    = f"{key}:{args}:{kwargs}" if args or kwargs else key
            cached_val  = _cache.get(full_key)
            if cached_val is not None:
                return cached_val
            result = func(*args, **kwargs)
            _cache.set(full_key, result, ttl)
            return result
        return wrapper
    return decorator


def invalidate(prefix: str):
    _cache.invalidate_prefix(prefix)


def cache_summary() -> dict:
    conn_stats = _cache.stats()
    keys = list(_cache._store.keys())
    return {**conn_stats, "keys": keys[:20]}
