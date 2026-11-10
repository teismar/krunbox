"""
Thread-safe background task runner for GTK4.
"""

import threading
from typing import Callable, Any, Optional
import gi
gi.require_version("GLib", "2.0")
from gi.repository import GLib

def run_async(
    worker_func: Callable[[], Any],
    on_success: Optional[Callable[[Any], None]] = None,
    on_error: Optional[Callable[[Exception], None]] = None
) -> None:
    """Execute worker_func on a background worker thread, dispatching callbacks to the GLib main loop."""
    def target():
        try:
            res = worker_func()
            if on_success:
                def _safe_success(result_to_report=res):
                    try:
                        on_success(result_to_report)
                    except Exception as err:
                        print(f"[krunbox-ui] Error in on_success callback: {err}")
                    return False
                GLib.idle_add(_safe_success)
        except Exception as e:
            exc = e
            if on_error:
                def _safe_error(error_to_report=exc):
                    try:
                        on_error(error_to_report)
                    except Exception as err:
                        print(f"[krunbox-ui] Error in on_error callback: {err}")
                    return False
                GLib.idle_add(_safe_error)
            else:
                print(f"[krunbox-ui] Error in background task: {exc}")

    t = threading.Thread(target=target, daemon=True)
    t.start()
