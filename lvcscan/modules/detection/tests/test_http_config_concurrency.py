"""Thread-safety of http_config under a concurrent (--threads N) detect phase."""
import threading

from modules.core import http_config as h


def test_active_module_is_thread_local():
    """Each thread's active-module label is isolated (no cross-attribution race)."""
    seen = {}
    barrier = threading.Barrier(4)

    def worker(name):
        h.set_active_module(name)
        barrier.wait()  # force interleaving: all set before any reads
        seen[name] = h._get_active_module()

    threads = [threading.Thread(target=worker, args=(f"cve-{i}",)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert seen == {f"cve-{i}": f"cve-{i}" for i in range(4)}


def test_request_stats_are_lock_safe():
    """Concurrent _record_request_stats never loses updates and attributes per-module correctly."""
    h.reset_request_stats()
    n_threads, per_thread = 8, 500

    def worker(name):
        h.set_active_module(name)
        for _ in range(per_thread):
            h._record_request_stats()

    threads = [threading.Thread(target=worker, args=(f"m{i}",)) for i in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    stats = h.get_request_stats()
    assert stats["total"] == n_threads * per_thread
    for i in range(n_threads):
        assert stats["module"][f"m{i}"] == per_thread
    h.reset_request_stats()
