"""
Adaptive Libadwaita dialog helpers and modern AlertDialog factory.
"""

from typing import Callable, List, Optional, Tuple, Union
import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gtk


def show_alert_dialog(
    parent_window: Gtk.Widget,
    heading: str,
    body: str,
    responses: List[Union[Tuple[str, str], Tuple[str, str, Adw.ResponseAppearance]]],
    on_response: Callable[[str], None],
    default_response: Optional[str] = None,
    close_response: Optional[str] = "cancel",
    extra_child: Optional[Gtk.Widget] = None,
) -> Union[Adw.AlertDialog, Adw.MessageDialog]:
    """
    Create, configure, and present a modern Adw.AlertDialog (Libadwaita 1.5+),
    with automatic graceful fallback to Adw.MessageDialog on older environments.
    """
    if hasattr(Adw, "AlertDialog"):
        dlg = Adw.AlertDialog(heading=heading, body=body)
    else:
        dlg = Adw.MessageDialog(transient_for=parent_window, heading=heading, body=body)

    for resp in responses:
        if len(resp) == 3:
            r_id, r_label, r_app = resp
            dlg.add_response(r_id, r_label)
            dlg.set_response_appearance(r_id, r_app)
        else:
            r_id, r_label = resp
            dlg.add_response(r_id, r_label)

    if default_response:
        dlg.set_default_response(default_response)
    if close_response:
        dlg.set_close_response(close_response)
    if extra_child is not None:
        dlg.set_extra_child(extra_child)

    def _wrapper(_d, resp_id: str):
        on_response(resp_id)

    dlg.connect("response", _wrapper)

    if hasattr(Adw, "AlertDialog") and isinstance(dlg, Adw.AlertDialog):
        dlg.present(parent_window)
    else:
        dlg.present()

    return dlg
