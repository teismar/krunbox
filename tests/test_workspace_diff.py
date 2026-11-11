"""
Automated unit, security, and headless GTK4 UI tests for Workspace Git Guardrails
and the Pre-Run Workspace Snapshot / Diff / Rollback subsystem.
"""

import hashlib
import os
from pathlib import Path
import stat
import subprocess
import time
import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, GLib, Gtk
import pytest

from krunbox.core.workspace_diff import (
    FileChange,
    WorkspaceSnapshotManager,
    build_git_guardrail_mounts,
)
from krunbox.ui.app import KrunboxApplication
from krunbox.ui.window import KrunboxWindow
from krunbox.ui.workspace_diff_dialog import WorkspaceChangesDialog


def _pump_gtk(ticks: int = 25, sleep_sec: float = 0.01) -> None:
    ctx = GLib.MainContext.default()
    for _ in range(ticks):
        while ctx.pending():
            ctx.iteration(False)
        time.sleep(sleep_sec)
        while ctx.pending():
            ctx.iteration(False)


def _init_git_repo(ws: Path) -> None:
    ws.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "-C", str(ws), "init"], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(ws), "config", "user.email", "test@krunbox.local"],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "-C", str(ws), "config", "user.name", "Krunbox Test"],
        check=True,
        capture_output=True,
    )


@pytest.fixture(scope="module")
def gtk_app():
    Adw.init()
    application = KrunboxApplication(application_id="io.krunbox.Krunbox.DiffTest")
    application.register()
    return application


# =========================================================================
# 1. Workspace Git Guardrails (`build_git_guardrail_mounts`)
# =========================================================================


def test_git_guardrail_mounts_default_hooks_and_missing_hooks(tmp_path):
    guardrails_dir = tmp_path / "guardrails"

    # Non-existent path -> empty
    assert build_git_guardrail_mounts(str(tmp_path / "does-not-exist")) == []

    # Plain directory without .git -> empty
    plain_ws = tmp_path / "plain"
    plain_ws.mkdir()
    assert build_git_guardrail_mounts(str(plain_ws), guardrails_dir=guardrails_dir) == []

    # Git repo with existing .git/hooks directory
    git_ws = tmp_path / "git_ws"
    _init_git_repo(git_ws)
    hooks_dir = (git_ws / ".git" / "hooks").resolve()
    assert hooks_dir.is_dir()

    mounts = build_git_guardrail_mounts(str(git_ws), guardrails_dir=guardrails_dir)
    assert mounts == ["-v", f"{hooks_dir}:/workspace/.git/hooks:ro"]

    # Git repo where .git exists as directory, but .git/hooks was removed prior to launch
    for child in hooks_dir.iterdir():
        if child.is_file() or child.is_symlink():
            child.unlink()
    hooks_dir.rmdir()
    assert not hooks_dir.exists()

    mounts_created = build_git_guardrail_mounts(str(git_ws), guardrails_dir=guardrails_dir)
    assert hooks_dir.is_dir()
    assert mounts_created == ["-v", f"{hooks_dir}:/workspace/.git/hooks:ro"]


def test_git_guardrail_mounts_symlinked_hooks_defense(tmp_path):
    guardrails_dir = tmp_path / "guardrails"
    outside_hooks = tmp_path / "outside_hooks"
    outside_hooks.mkdir()
    (outside_hooks / "post-checkout").write_text("#!/bin/sh\necho pwned\n")

    git_ws = tmp_path / "repo_symlink_hooks"
    (git_ws / ".git").mkdir(parents=True)
    (git_ws / ".git" / "hooks").symlink_to(outside_hooks)

    mounts = build_git_guardrail_mounts(str(git_ws), guardrails_dir=guardrails_dir)
    empty_hooks = guardrails_dir / "empty_hooks"
    assert mounts == ["-v", f"{empty_hooks}:/workspace/.git/hooks:ro"]
    assert empty_hooks.is_dir()
    assert list(empty_hooks.iterdir()) == []
    assert stat.S_IMODE(guardrails_dir.stat().st_mode) == 0o700


def test_git_guardrail_mounts_config_and_env_filtering(tmp_path):
    guardrails_dir = tmp_path / "guardrails"
    ws = tmp_path / "repo_full_guardrails"
    _init_git_repo(ws)

    # Create real .env files, template files, and a malicious symlink .env.evil
    (ws / ".env").write_text("API_KEY=secret1\n")
    (ws / ".env.local").write_text("DB_PASS=secret2\n")
    (ws / ".env.production").write_text("PROD_TOKEN=secret3\n")
    (ws / ".env.example").write_text("API_KEY=changeme\n")
    (ws / ".env.sample").write_text("API_KEY=sample\n")
    (ws / ".env.template").write_text("API_KEY=tmpl\n")
    (ws / ".env.dist").write_text("API_KEY=dist\n")

    outside_secret = tmp_path / "outside_secret.txt"
    outside_secret.write_text("TOP_SECRET")
    (ws / ".env.symlink").symlink_to(outside_secret)

    mounts = build_git_guardrail_mounts(
        str(ws),
        protect_git_hooks=True,
        protect_git_config=True,
        protect_env_files=True,
        guardrails_dir=guardrails_dir,
    )

    ws_res = ws.resolve()
    expected = [
        "-v",
        f"{ws_res / '.git' / 'hooks'}:/workspace/.git/hooks:ro",
        "-v",
        f"{ws_res / '.git' / 'config'}:/workspace/.git/config:ro",
        "-v",
        f"{ws_res / '.env'}:/workspace/.env:ro",
        "-v",
        f"{ws_res / '.env.local'}:/workspace/.env.local:ro",
        "-v",
        f"{ws_res / '.env.production'}:/workspace/.env.production:ro",
    ]
    assert mounts == expected


# =========================================================================
# 2. WorkspaceSnapshotManager - Git Mode
# =========================================================================


def test_snapshot_manager_git_mode_preserves_index_and_tracks_all_changes(tmp_path):
    snap_root = tmp_path / "snapshots"
    mgr = WorkspaceSnapshotManager(snapshots_dir=snap_root)

    ws = tmp_path / "git_project"
    _init_git_repo(ws)

    (ws / "app.py").write_text("def greet():\n    return 'hello'\n")
    (ws / "README.md").write_text("# Demo Project\nLine two\n")
    (ws / "scripts").mkdir()
    deploy_sh = ws / "scripts" / "deploy.sh"
    deploy_sh.write_text("#!/bin/sh\necho deploying\n")
    deploy_sh.chmod(0o755)
    (ws / "movable.py").write_text(
        "alpha = 1\nbeta = 2\ngamma = 3\ndelta = 4\nepsilon = 5\n"
    )
    (ws / "logo.bin").write_bytes(b"\x89PNG\r\n\x1a\n\x00\x01\x02\x03")

    subprocess.run(["git", "-C", str(ws), "add", "-A"], check=True)
    subprocess.run(
        ["git", "-C", str(ws), "commit", "-m", "Initial commit"],
        check=True,
        capture_output=True,
    )

    # Pre-existing untracked file + unstaged edit before sandbox launch
    (ws / "local_notes.txt").write_text("keep me in baseline\n")

    index_file = ws / ".git" / "index"
    index_sha_before = hashlib.sha256(index_file.read_bytes()).hexdigest()
    status_before = subprocess.run(
        ["git", "-C", str(ws), "status", "--porcelain"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout

    ok, msg, meta = mgr.create_snapshot("box-git-alpha", str(ws))
    assert ok is True
    assert "Git" in msg
    assert meta["mode"] == "git"
    assert len(meta["tree_sha"]) == 40
    assert len(meta["head_sha"]) == 40
    assert "local_notes.txt" in meta["untracked_files"]

    # Verify real .git/index and git status were NOT altered by snapshot creation!
    index_sha_after_snap = hashlib.sha256(index_file.read_bytes()).hexdigest()
    status_after_snap = subprocess.run(
        ["git", "-C", str(ws), "status", "--porcelain"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    assert index_sha_after_snap == index_sha_before
    assert status_after_snap == status_before

    # Clean immediately after snapshot
    assert mgr.list_changes("box-git-alpha", str(ws)) == []

    # Simulate agent edits inside /workspace:
    # 1. Modify app.py
    (ws / "app.py").write_text("def greet(name='world'):\n    return f'hello {name}'\n    # extra\n")
    # 2. Add new untracked file in nested subdir
    (ws / "generated" / "nested").mkdir(parents=True)
    (ws / "generated" / "nested" / "agent_out.py").write_text("x = 42\ny = 99\n")
    # 3. Delete README.md and executable scripts/deploy.sh
    (ws / "README.md").unlink()
    deploy_sh.unlink()
    # 4. Rename movable.py -> pkg/moved.py with minor modification
    (ws / "movable.py").unlink()
    (ws / "pkg").mkdir()
    (ws / "pkg" / "moved.py").write_text(
        "alpha = 1\nbeta = 2\ngamma = 3\ndelta = 4\nepsilon = 5\nzeta = 6\n"
    )
    # 5. Modify binary file
    (ws / "logo.bin").write_bytes(b"\x89PNG\r\n\x1a\n\x00\xff\xfe\xfd")

    changes = mgr.list_changes("box-git-alpha", str(ws))
    # Verify real .git/index STILL untouched after list_changes!
    assert hashlib.sha256(index_file.read_bytes()).hexdigest() == index_sha_before

    by_path = {c.path: c for c in changes}
    assert by_path["app.py"].status == "modified"
    assert by_path["app.py"].additions == 3
    assert by_path["app.py"].deletions == 2

    assert by_path["generated/nested/agent_out.py"].status == "added"
    assert by_path["generated/nested/agent_out.py"].additions == 2
    assert by_path["generated/nested/agent_out.py"].deletions == 0

    assert by_path["README.md"].status == "deleted"
    assert by_path["README.md"].deletions == 2

    assert by_path["scripts/deploy.sh"].status == "deleted"

    assert by_path["pkg/moved.py"].status == "renamed"
    assert by_path["pkg/moved.py"].old_path == "movable.py"
    assert by_path["pkg/moved.py"].additions == 1

    assert by_path["logo.bin"].status == "modified"

    # Unified diff checks
    app_diff = mgr.get_file_diff("box-git-alpha", str(ws), "app.py")
    assert "--- a/app.py" in app_diff
    assert "+++ b/app.py" in app_diff
    assert "-    return 'hello'" in app_diff
    assert "+    return f'hello {name}'" in app_diff

    bin_diff = mgr.get_file_diff("box-git-alpha", str(ws), "logo.bin")
    assert "Binary file changed" in bin_diff

    # Diff truncation check
    (ws / "large.txt").write_text("\n".join(f"line-{i}" for i in range(500)) + "\n")
    trunc_diff = mgr.get_file_diff("box-git-alpha", str(ws), "large.txt", max_bytes=150)
    assert "truncated" in trunc_diff
    (ws / "large.txt").unlink()

    # Revert individual added file -> unlinked AND empty parent dirs pruned
    rev_ok, _ = mgr.revert_file("box-git-alpha", str(ws), "generated/nested/agent_out.py")
    assert rev_ok is True
    assert not (ws / "generated").exists()

    # Revert deleted executable file -> restored with 0o755 mode
    rev_sh_ok, _ = mgr.revert_file("box-git-alpha", str(ws), "scripts/deploy.sh")
    assert rev_sh_ok is True
    assert deploy_sh.is_file()
    assert (deploy_sh.stat().st_mode & 0o111) != 0

    # Revert renamed file -> removes pkg/moved.py and restores movable.py
    rev_ren_ok, _ = mgr.revert_file("box-git-alpha", str(ws), "pkg/moved.py")
    assert rev_ren_ok is True
    assert not (ws / "pkg" / "moved.py").exists()
    assert (ws / "movable.py").is_file()

    # Rollback all remaining changes (app.py, README.md, logo.bin)
    rb_ok, rb_msg = mgr.rollback_all("box-git-alpha", str(ws))
    assert rb_ok is True
    assert "Rolled back 3 file(s)" in rb_msg
    assert (ws / "app.py").read_text() == "def greet():\n    return 'hello'\n"
    assert (ws / "README.md").read_text() == "# Demo Project\nLine two\n"
    assert (ws / "local_notes.txt").read_text() == "keep me in baseline\n"
    assert mgr.list_changes("box-git-alpha", str(ws)) == []

    # Idempotent rollback when already clean
    rb_clean_ok, rb_clean_msg = mgr.rollback_all("box-git-alpha", str(ws))
    assert rb_clean_ok is True
    assert rb_clean_msg == "Workspace already matches baseline snapshot."

    # Accept changes advances baseline snapshot
    (ws / "accepted_feature.py").write_text("accepted = True\n")
    assert len(mgr.list_changes("box-git-alpha", str(ws))) == 1
    acc_ok, _ = mgr.accept_changes("box-git-alpha", str(ws))
    assert acc_ok is True
    assert mgr.list_changes("box-git-alpha", str(ws)) == []

    # Rename & delete snapshot lifecycle
    mgr.rename_snapshot("box-git-alpha", "box-git-renamed")
    assert mgr.get_snapshot_info("box-git-alpha") is None
    renamed_info = mgr.get_snapshot_info("box-git-renamed")
    assert renamed_info is not None
    assert renamed_info["sandbox_name"] == "box-git-renamed"

    mgr.delete_snapshot("box-git-renamed")
    assert mgr.get_snapshot_info("box-git-renamed") is None


def test_snapshot_manager_git_unborn_head_fallback(tmp_path):
    mgr = WorkspaceSnapshotManager(snapshots_dir=tmp_path / "snapshots")
    ws = tmp_path / "unborn_repo"
    _init_git_repo(ws)
    (ws / "draft.txt").write_text("uncommitted work\n")

    # Even before create_snapshot, list_changes works against empty tree!
    pre_changes = mgr.list_changes("box-unborn", str(ws))
    assert len(pre_changes) == 1
    assert pre_changes[0].path == "draft.txt"
    assert pre_changes[0].status == "added"

    meta = mgr.ensure_snapshot("box-unborn", str(ws))
    assert meta["mode"] == "git"
    assert meta["head_sha"] is None
    assert mgr.list_changes("box-unborn", str(ws)) == []


# =========================================================================
# 3. Path Traversal & Symlink Escape Rejection
# =========================================================================


def test_path_traversal_and_symlink_escape_rejection(tmp_path):
    mgr = WorkspaceSnapshotManager(snapshots_dir=tmp_path / "snapshots")
    ws = tmp_path / "secure_ws"
    ws.mkdir()
    (ws / "legit.txt").write_text("safe\n")

    outside_file = tmp_path / "outside.txt"
    outside_file.write_text("HOST_SENSITIVE_DATA\n")
    outside_dir = tmp_path / "outside_dir"
    outside_dir.mkdir()
    (outside_dir / "target.txt").write_text("OUTSIDE_DIR_SECRET\n")

    mgr.create_snapshot("box-sec", str(ws))

    # Create symlinks inside workspace pointing outside
    (ws / "symlink_file.txt").symlink_to(outside_file)
    (ws / "symlink_dir").symlink_to(outside_dir)

    malicious_paths = [
        "",
        "/etc/passwd",
        "../outside.txt",
        "sub/../../outside.txt",
        "\\evil\\path.txt",
        ".git/config",
        "symlink_file.txt",
        "symlink_dir/target.txt",
        "symlink_dir/new_drop.txt",
    ]

    for bad_path in malicious_paths:
        with pytest.raises(ValueError):
            mgr._validate_rel_path(ws, bad_path)

        with pytest.raises(ValueError):
            mgr.get_file_diff("box-sec", str(ws), bad_path)

        ok, err_msg = mgr.revert_file("box-sec", str(ws), bad_path)
        assert ok is False
        assert err_msg

    # Verify host files outside workspace were never read, overwritten, or deleted
    assert outside_file.read_text() == "HOST_SENSITIVE_DATA\n"
    assert (outside_dir / "target.txt").read_text() == "OUTSIDE_DIR_SECRET\n"


# =========================================================================
# 4. WorkspaceSnapshotManager - Non-Git Archive Fallback Mode
# =========================================================================


def test_snapshot_manager_archive_mode_end_to_end(tmp_path):
    snap_root = tmp_path / "snapshots"
    mgr = WorkspaceSnapshotManager(snapshots_dir=snap_root)

    ws = tmp_path / "plain_workspace"
    ws.mkdir()
    (ws / "main.py").write_text("print('v1')\nline2 = True\n")
    (ws / "cfg").mkdir()
    (ws / "cfg" / "config.json").write_text('{"port": 8080}\n')
    run_tool = ws / "run_tool.sh"
    run_tool.write_text("#!/bin/sh\necho ok\n")
    run_tool.chmod(0o755)

    # Ignored vendor/cache directories and symlinks should be skipped cleanly
    (ws / "node_modules" / "pkg").mkdir(parents=True)
    (ws / "node_modules" / "pkg" / "index.js").write_text("module.exports = {};\n")
    (ws / "__pycache__").mkdir()
    (ws / "__pycache__" / "main.cpython-312.pyc").write_bytes(b"\x00\x01\x02")

    ok, msg, meta = mgr.create_snapshot("box-archive", str(ws))
    assert ok is True
    assert "archive" in msg.lower()
    assert meta["mode"] == "archive"
    assert meta["file_count"] == 3
    assert mgr.list_changes("box-archive", str(ws)) == []

    # Mutate plain workspace
    (ws / "main.py").write_text("print('v2')\nline2 = True\nline3 = 'added'\n")
    (ws / "cfg" / "config.json").unlink()
    run_tool.unlink()
    (ws / "extra" / "sub").mkdir(parents=True)
    (ws / "extra" / "sub" / "notes.md").write_text("# Agent Notes\nItem 1\n")

    changes = mgr.list_changes("box-archive", str(ws))
    by_path = {c.path: c for c in changes}
    assert set(by_path.keys()) == {
        "main.py",
        "cfg/config.json",
        "run_tool.sh",
        "extra/sub/notes.md",
    }
    assert by_path["main.py"].status == "modified"
    assert by_path["main.py"].additions == 2
    assert by_path["main.py"].deletions == 1
    assert by_path["cfg/config.json"].status == "deleted"
    assert by_path["cfg/config.json"].deletions == 1
    assert by_path["extra/sub/notes.md"].status == "added"
    assert by_path["extra/sub/notes.md"].additions == 2

    diff_txt = mgr.get_file_diff("box-archive", str(ws), "main.py")
    assert "-print('v1')" in diff_txt
    assert "+print('v2')" in diff_txt

    # Revert single executable file and verify mode 0o755 preserved
    ok_rev, _ = mgr.revert_file("box-archive", str(ws), "run_tool.sh")
    assert ok_rev is True
    assert run_tool.is_file()
    assert (run_tool.stat().st_mode & 0o111) != 0

    # Rollback remaining 3 changes
    ok_rb, msg_rb = mgr.rollback_all("box-archive", str(ws))
    assert ok_rb is True
    assert "Rolled back 3 file(s)" in msg_rb
    assert (ws / "main.py").read_text() == "print('v1')\nline2 = True\n"
    assert (ws / "cfg" / "config.json").read_text() == '{"port": 8080}\n'
    assert not (ws / "extra").exists()
    assert mgr.list_changes("box-archive", str(ws)) == []


# =========================================================================
# 5. Headless GTK4 / Libadwaita 1.5 UI Tests (`WorkspaceChangesDialog`)
# =========================================================================


def test_workspace_changes_dialog_headless_ui_workflow(gtk_app, tmp_path):
    snap_mgr = WorkspaceSnapshotManager(snapshots_dir=tmp_path / "ui_snapshots")
    ws = tmp_path / "ui_ws"
    ws.mkdir()
    (ws / "service.py").write_text("PORT = 8000\nDEBUG = False\n")
    (ws / "a&b<special>.txt").write_text("line1\n")

    parent_win = KrunboxWindow(gtk_app)
    changed_events: list = []

    # 1. Open dialog BEFORE a snapshot exists -> Banner offers "Create Snapshot"
    dlg_no_snap = WorkspaceChangesDialog(
        parent_win,
        snap_mgr,
        sandbox_name="worker-ui-test",
        dir_path=str(ws),
        on_changed=lambda: changed_events.append("changed"),
    )
    dlg_no_snap.present()
    _pump_gtk()

    assert dlg_no_snap.get_title() == "Workspace Changes - worker-ui-test"
    assert dlg_no_snap.info_banner.get_revealed() is True
    assert dlg_no_snap.info_banner.get_use_markup() is False
    assert dlg_no_snap.info_banner.get_button_label() == "Create Snapshot"

    # Trigger "Create Snapshot" via banner button
    dlg_no_snap.info_banner.emit("button-clicked")
    _pump_gtk(35)
    assert snap_mgr.get_snapshot_info("worker-ui-test") is not None
    assert dlg_no_snap.stack.get_visible_child_name() == "empty"
    dlg_no_snap.close()
    _pump_gtk()
    assert dlg_no_snap._closed is True

    # 2. Modify, add, and delete files in workspace, then open dialog
    (ws / "service.py").write_text("PORT = 9090\nDEBUG = True\nWORKERS = 4\n")
    (ws / "added_by_agent.txt").write_text("hello from agent\n")
    (ws / "a&b<special>.txt").unlink()

    dlg = WorkspaceChangesDialog(
        parent_win,
        snap_mgr,
        sandbox_name="worker-ui-test",
        dir_path=str(ws),
        on_changed=lambda: changed_events.append("updated"),
    )
    dlg.present()
    _pump_gtk(35)

    assert dlg.stack.get_visible_child_name() == "populated"
    assert dlg.rollback_btn.get_sensitive() is True
    assert len(dlg.changes) == 3

    # Select service.py row and inspect highlighted unified diff in TextView
    idx = 0
    service_row = None
    while True:
        row = dlg.file_list.get_row_at_index(idx)
        if row is None:
            break
        if row.change.path == "service.py":
            service_row = row
        idx += 1
    assert idx == 3
    assert service_row is not None

    dlg.file_list.select_row(service_row)
    _pump_gtk(30)

    start_it = dlg.diff_buffer.get_start_iter()
    end_it = dlg.diff_buffer.get_end_iter()
    rendered_diff = dlg.diff_buffer.get_text(start_it, end_it, False)
    assert "-PORT = 8000" in rendered_diff
    assert "+PORT = 9090" in rendered_diff
    assert "@@" in rendered_diff

    tag_table = dlg.diff_buffer.get_tag_table()
    assert tag_table.lookup("diff-add") is not None
    assert tag_table.lookup("diff-del") is not None
    assert tag_table.lookup("diff-hunk") is not None

    # Revert currently selected file ("service.py") via "Revert File" button
    dlg.revert_file_btn.emit("clicked")
    _pump_gtk(35)
    assert (ws / "service.py").read_text() == "PORT = 8000\nDEBUG = False\n"
    assert len(dlg.changes) == 2

    # Click "Rollback All…" -> opens Adw.MessageDialog confirmation -> confirm "rollback"
    dlg.rollback_btn.emit("clicked")
    _pump_gtk(15)
    confirm_dlg = dlg._active_confirm_dialog
    assert confirm_dlg is not None
    confirm_dlg.emit("response", "rollback")
    confirm_dlg.close()
    _pump_gtk(35)

    assert dlg.stack.get_visible_child_name() == "empty"
    assert dlg.rollback_btn.get_sensitive() is False
    assert not (ws / "added_by_agent.txt").exists()
    assert (ws / "a&b<special>.txt").read_text() == "line1\n"

    # Make an intentional edit and click "Accept Baseline"
    (ws / "kept.txt").write_text("intentionally kept\n")
    dlg.refresh_btn.emit("clicked")
    _pump_gtk(30)
    assert dlg.stack.get_visible_child_name() == "populated"

    dlg.accept_btn.emit("clicked")
    _pump_gtk(35)
    assert dlg.stack.get_visible_child_name() == "empty"
    assert snap_mgr.list_changes("worker-ui-test", str(ws)) == []
    assert "updated" in changed_events

    dlg.close()
    parent_win.close()
    _pump_gtk()


def test_workspace_changes_dialog_zero_gtk_markup_warnings(gtk_app, tmp_path, capfd):
    """Ensure special characters (&, <, >) in sandbox names and file paths emit zero GTK markup warnings."""
    snap_mgr = WorkspaceSnapshotManager(snapshots_dir=tmp_path / "markup_snaps")
    ws = tmp_path / "markup_ws"
    ws.mkdir()
    (ws / "cfg&<tag>.ini").write_text("k=1\n")
    snap_mgr.create_snapshot("box&<1>", str(ws))
    (ws / "cfg&<tag>.ini").write_text("k=2\n")

    capfd.readouterr()

    parent_win = KrunboxWindow(gtk_app)
    dlg = WorkspaceChangesDialog(
        parent_win,
        snap_mgr,
        sandbox_name="box&<1>",
        dir_path=str(ws),
    )
    dlg.present()
    _pump_gtk(30)
    dlg.rollback_btn.emit("clicked")
    _pump_gtk(10)
    if dlg._active_confirm_dialog is not None:
        dlg._active_confirm_dialog.close()
    dlg.close()
    parent_win.close()
    _pump_gtk(15)

    _out, err = capfd.readouterr()
    assert "markup" not in err.lower()
    assert "pango-warning" not in err.lower()
    assert "critical" not in err.lower()

