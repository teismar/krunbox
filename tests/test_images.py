"""
Unit tests for base image manager.
"""

from unittest.mock import MagicMock, patch
from pathlib import Path
import datetime
from krunbox.core.images import ImageManager
from krunbox.core.config import BUILTIN_IMAGES
from krunbox.cli.commands import cmd_images

def test_image_manager_listing():
    mgr = ImageManager()
    images = mgr.list_images()
    assert len(images) >= len(BUILTIN_IMAGES)
    ids = [img["id"] for img in images]
    assert "agent-box" in ids
    assert "python-data" in ids
    assert "node-fullstack" in ids
    assert "debian-minimal" in ids
    assert "reversing" in ids


def test_build_base_image():
    mgr = ImageManager()
    with patch.object(mgr, "_run_podman_build", return_value=(True, "Successfully built localhost/krunbox-base:latest")) as mock_build:
        ok, msg = mgr.build_base_image("/workspace/images/base/Containerfile")
        assert ok is True
        assert "Successfully built" in msg
        mock_build.assert_called_once()
        assert mock_build.call_args[0][0] == "localhost/krunbox-base:latest"


def test_build_reversing_image():
    mgr = ImageManager()
    with patch.object(mgr, "_get_local_podman_tags", return_value=["localhost/krunbox-base:latest"]), \
         patch.object(mgr, "_run_podman_build", return_value=(True, "Successfully built localhost/krunbox-reversing:latest")) as mock_build:
        ok, msg = mgr.build_reversing_image("/workspace/images/reversing/Containerfile")
        assert ok is True
        assert "Successfully built" in msg
        mock_build.assert_called_once()
        assert mock_build.call_args[0][0] == "localhost/krunbox-reversing:latest"


def test_build_python_image():
    mgr = ImageManager()
    with patch.object(mgr, "_get_local_podman_tags", return_value=["localhost/krunbox-base:latest"]), \
         patch.object(mgr, "_run_podman_build", return_value=(True, "Successfully built localhost/krunbox-python:latest")) as mock_build:
        ok, msg = mgr.build_python_image("/workspace/images/python/Containerfile")
        assert ok is True
        assert "Successfully built" in msg
        mock_build.assert_called_once()
        assert mock_build.call_args[0][0] == "localhost/krunbox-python:latest"


def test_build_image_target_dispatch():
    mgr = ImageManager()
    with patch.object(mgr, "build_base_image", return_value=(True, "ok base")) as mock_base, \
         patch.object(mgr, "build_python_image", return_value=(True, "ok python")) as mock_py, \
         patch.object(mgr, "build_node_image", return_value=(True, "ok node")) as mock_node, \
         patch.object(mgr, "build_reversing_image", return_value=(True, "ok reversing")) as mock_rev, \
         patch.object(mgr, "build_agent_box", return_value=(True, "ok agent")) as mock_agent:

        assert mgr.build_image("base")[0] is True
        mock_base.assert_called_once()

        assert mgr.build_image("python-data")[0] is True
        mock_py.assert_called_once()

        assert mgr.build_image("node")[0] is True
        mock_node.assert_called_once()

        assert mgr.build_image("reversing")[0] is True
        mock_rev.assert_called_once()

        assert mgr.build_image("agent-box")[0] is True
        mock_agent.assert_called_once()

        ok, msg = mgr.build_image("nonexistent")
        assert ok is False
        assert "Unknown image target" in msg


def test_cmd_images_build_action():
    mgr = ImageManager()
    with patch.object(mgr, "build_image", return_value=(True, "Built base")):
        rc = cmd_images(mgr, action="build", target="base")
        assert rc == 0

    with patch.object(mgr, "build_image", return_value=(False, "Failed")):
        rc = cmd_images(mgr, action="build", target="invalid")
        assert rc == 1


def test_should_build_or_update_missing():
    mgr = ImageManager()
    with patch.object(mgr, "is_image_present", return_value=False):
        needs, reason = mgr.should_build_or_update("python-data")
        assert needs is True
        assert "not found locally" in reason


def test_should_build_or_update_older_than_limit():
    mgr = ImageManager()
    old_time = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=20)
    with patch.object(mgr, "is_image_present", return_value=True), \
         patch.object(mgr, "get_image_created_at", return_value=old_time):
        needs, reason = mgr.should_build_or_update("debian-minimal", max_age_days=14)
        assert needs is True
        assert "older than 14 days" in reason or "exceeds" in reason


def test_should_build_or_update_spec_modified():
    mgr = ImageManager()
    past_build = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)
    with patch.object(mgr, "is_image_present", return_value=True), \
         patch.object(mgr, "get_image_created_at", return_value=past_build), \
         patch.object(mgr, "get_spec_mtime", return_value=past_build.timestamp() + 3600):
        needs, reason = mgr.should_build_or_update("debian-minimal", max_age_days=14)
        assert needs is True
        assert "modified after image build" in reason


def test_should_build_or_update_spec_hash_changed():
    mgr = ImageManager()
    recent = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1)
    with patch.object(mgr, "is_image_present", return_value=True), \
         patch.object(mgr, "get_image_created_at", return_value=recent), \
         patch.object(mgr, "get_spec_mtime", return_value=recent.timestamp() - 100), \
         patch.object(mgr, "compute_spec_hash", return_value="hash_new"), \
         patch.object(mgr, "get_build_metadata", return_value={"spec_hash": "hash_old"}):
        needs, reason = mgr.should_build_or_update("debian-minimal", max_age_days=14)
        assert needs is True
        assert "content changed" in reason


def test_ensure_image_ready_skips_when_fresh():
    mgr = ImageManager()
    with patch.object(mgr, "should_build_or_update", return_value=(False, "Image is up to date")), \
         patch.object(mgr, "build_image") as mock_build:
        ok, msg = mgr.ensure_image_ready("python-data")
        assert ok is True
        assert "ready" in msg
        mock_build.assert_not_called()


def test_ensure_image_ready_builds_when_needed():
    mgr = ImageManager()
    with patch.object(mgr, "should_build_or_update", return_value=(True, "not found locally")), \
         patch.object(mgr, "build_image", return_value=(True, "Built python-data")) as mock_build:
        ok, msg = mgr.ensure_image_ready("debian-minimal")
        assert ok is True
        assert "Built" in msg
        mock_build.assert_called_once_with("debian-minimal")


def test_cmd_images_check_action():
    mgr = ImageManager()
    with patch.object(mgr, "list_images", return_value=[
        {"id": "python-data", "is_present": True, "needs_rebuild": False, "age_days": 1.0, "rebuild_reason": "Ready"}
    ]):
        rc = cmd_images(mgr, action="check")
        assert rc == 0


def test_run_podman_build_uses_pasta(tmp_path):
    """Ensure _run_podman_build invokes podman build with --net=pasta instead of slirp4netns."""
    mgr = ImageManager()
    dummy_file = tmp_path / "Containerfile"
    dummy_file.write_text("FROM scratch\n")

    with patch("subprocess.run") as mock_run:
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = "Successfully built test:tag\n"
        mock_proc.stderr = ""
        mock_run.return_value = mock_proc

        ok, msg = mgr._run_podman_build("test:tag", dummy_file, tmp_path)
        assert ok is True
        assert "Successfully built" in msg
        assert mock_run.call_count >= 1
        build_cmd = mock_run.call_args_list[0][0][0]
        assert "--net=pasta" in build_cmd
        assert "--net=slirp4netns" not in build_cmd


def test_zero_slirp_references_invariant():
    """Invariant test: Zero occurrences of slirp or slirp4netns in krunbox code and docs."""
    workspace_root = Path(__file__).resolve().parent.parent
    for py_file in (workspace_root / "krunbox").rglob("*.py"):
        content = py_file.read_text(encoding="utf-8").lower()
        assert "slirp" not in content, f"Found forbidden 'slirp' reference in {py_file}"


def test_cmd_images_build_all_action():
    """Ensure cmd_images build all displays progress and handles all-success and partial-failure."""
    mgr = ImageManager()
    success_results = [
        ("base", True, "Successfully built localhost/krunbox-base:latest"),
        ("python", True, "Successfully built localhost/krunbox-python:latest"),
        ("node", True, "Successfully built localhost/krunbox-node:latest"),
        ("agent-box", True, "Successfully built localhost/agent-box:latest"),
    ]
    with patch.object(mgr, "build_all_images", return_value=success_results):
        rc = cmd_images(mgr, action="build", target="all")
        assert rc == 0

    fail_results = [
        ("base", True, "Successfully built localhost/krunbox-base:latest"),
        ("python", False, "Build error: package not found"),
    ]
    with patch.object(mgr, "build_all_images", return_value=fail_results):
        rc = cmd_images(mgr, action="build", target="all")
        assert rc == 1


def test_build_all_images_invokes_progress_callbacks():
    """Verify build_all_images forwards progress and image_complete callbacks."""
    mgr = ImageManager()
    with patch.object(mgr, "build_base_image", return_value=(True, "ok base")) as m_base, \
         patch.object(mgr, "build_python_image", return_value=(True, "ok py")) as m_py, \
         patch.object(mgr, "build_node_image", return_value=(True, "ok node")) as m_node, \
         patch.object(mgr, "build_reversing_image", return_value=(True, "ok reversing")) as m_rev, \
         patch.object(mgr, "build_agent_box", return_value=(True, "ok agent")) as m_agent:

        steps = []
        completed = []

        def on_step(target, line):
            steps.append((target, line))

        def on_done(target, ok, msg):
            completed.append((target, ok, msg))

        results = mgr.build_all_images(on_progress=on_step, on_image_complete=on_done)
        assert len(results) == 5
        assert len(completed) == 5
        assert [c[0] for c in completed] == ["base", "python", "node", "reversing", "agent-box"]


def test_run_podman_build_streaming_progress(tmp_path):
    """Verify _run_podman_build streams stdout lines to on_progress via Popen."""
    import io
    mgr = ImageManager()
    dummy_file = tmp_path / "Containerfile"
    dummy_file.write_text("FROM scratch\n")

    lines_received = []

    def progress_cb(line):
        lines_received.append(line)

    mock_popen_obj = MagicMock()
    mock_popen_obj.returncode = 0
    mock_popen_obj.stdout = io.StringIO("STEP 1/2: FROM scratch\nSTEP 2/2: RUN echo ok\nSuccessfully built\n")
    mock_popen_obj.wait.return_value = 0

    with patch("subprocess.Popen", return_value=mock_popen_obj) as mock_popen, \
         patch.object(mgr, "save_build_metadata"):
        ok, msg = mgr._run_podman_build("test:stream", dummy_file, tmp_path, on_progress=progress_cb)
        assert ok is True
        mock_popen.assert_called_once()
        assert len(lines_received) == 3
        assert "STEP 1/2: FROM scratch" in lines_received
        assert "STEP 2/2: RUN echo ok" in lines_received


