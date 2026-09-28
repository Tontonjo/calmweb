"""Tests for the calmweb.updater module.

All HTTP calls are mocked — no real network traffic.
"""

from __future__ import annotations

import json
import sys
import tempfile
import types
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from calmweb.updater import (
    UpdateCheckError,
    UpdateInfo,
    apply_update,
    check_for_update,
    download_installer,
)


class TestCheckForUpdate:
    """Tests for check_for_update()."""

    def _make_release_json(
        self,
        tag: str = "v2.0.0",
        asset_name: str = "CalmWeb_Setup.exe",
        asset_size: int = 5_000_000,
        body: str = "Bug fixes",
    ) -> bytes:
        """Helper to create a fake GitHub release JSON response."""
        return json.dumps(
            {
                "tag_name": tag,
                "html_url": f"https://github.com/Tontonjo/calmweb/releases/tag/{tag}",
                "body": body,
                "assets": [
                    {
                        "name": asset_name,
                        "browser_download_url": (
                            f"https://github.com/Tontonjo/calmweb/releases/download/{tag}/{asset_name}"
                        ),
                        "size": asset_size,
                    }
                ],
            }
        ).encode("utf-8")

    @patch("calmweb.updater.urllib3.PoolManager")
    @patch("calmweb.updater.__version__", "1.3.0")
    def test_update_available(self, mock_pool_cls: MagicMock) -> None:
        """When remote version > local, return UpdateInfo."""
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.data = self._make_release_json("v2.0.0")
        mock_pool_cls.return_value.request.return_value = mock_resp

        result = check_for_update()

        assert result is not None
        assert result.version == "2.0.0"
        assert "CalmWeb_Setup.exe" in result.download_url
        assert result.release_notes == "Bug fixes"

    @patch("calmweb.updater.urllib3.PoolManager")
    @patch("calmweb.updater.__version__", "2.0.0")
    def test_already_up_to_date(self, mock_pool_cls: MagicMock) -> None:
        """When remote version < local, return None."""
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.data = self._make_release_json("v1.3.0")
        mock_pool_cls.return_value.request.return_value = mock_resp

        result = check_for_update()
        assert result is None

    @patch("calmweb.updater.urllib3.PoolManager")
    @patch("calmweb.updater.__version__", "2.0.0")
    def test_same_version(self, mock_pool_cls: MagicMock) -> None:
        """When remote == local, return None."""
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.data = self._make_release_json("v2.0.0")
        mock_pool_cls.return_value.request.return_value = mock_resp

        result = check_for_update()
        assert result is None

    @patch("calmweb.updater.urllib3.PoolManager")
    def test_network_error(self, mock_pool_cls: MagicMock) -> None:
        """Network errors raise UpdateCheckError."""
        mock_pool_cls.return_value.request.side_effect = Exception("Connection refused")

        with pytest.raises(UpdateCheckError, match="Network error"):
            check_for_update()

    @patch("calmweb.updater.urllib3.PoolManager")
    def test_api_rate_limit(self, mock_pool_cls: MagicMock) -> None:
        """HTTP 403 raises UpdateCheckError about rate limit."""
        mock_resp = MagicMock()
        mock_resp.status = 403
        mock_resp.data = b""
        mock_pool_cls.return_value.request.return_value = mock_resp

        with pytest.raises(UpdateCheckError, match="rate limit"):
            check_for_update()

    @patch("calmweb.updater.urllib3.PoolManager")
    def test_no_releases(self, mock_pool_cls: MagicMock) -> None:
        """HTTP 404 raises UpdateCheckError."""
        mock_resp = MagicMock()
        mock_resp.status = 404
        mock_resp.data = b""
        mock_pool_cls.return_value.request.return_value = mock_resp

        with pytest.raises(UpdateCheckError, match="No releases"):
            check_for_update()

    @patch("calmweb.updater.urllib3.PoolManager")
    def test_unexpected_status_code(self, mock_pool_cls: MagicMock) -> None:
        """HTTP 500 raises UpdateCheckError with the status code."""
        mock_resp = MagicMock()
        mock_resp.status = 500
        mock_resp.data = b""
        mock_pool_cls.return_value.request.return_value = mock_resp

        with pytest.raises(UpdateCheckError, match="HTTP 500"):
            check_for_update()

    @patch("calmweb.updater.urllib3.PoolManager")
    @patch("calmweb.updater.__version__", "1.0.0")
    def test_no_exe_asset(self, mock_pool_cls: MagicMock) -> None:
        """Release without .exe asset raises UpdateCheckError."""
        release_data = json.dumps(
            {
                "tag_name": "v2.0.0",
                "html_url": "https://github.com/Tontonjo/calmweb/releases/tag/v2.0.0",
                "body": "Notes",
                "assets": [
                    {
                        "name": "source.tar.gz",
                        "browser_download_url": "https://example.com/source.tar.gz",
                        "size": 1000,
                    }
                ],
            }
        ).encode("utf-8")

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.data = release_data
        mock_pool_cls.return_value.request.return_value = mock_resp

        with pytest.raises(UpdateCheckError, match="no installer"):
            check_for_update()

    @patch("calmweb.updater.urllib3.PoolManager")
    @patch("calmweb.updater.__version__", "1.0.0")
    def test_tag_without_v_prefix(self, mock_pool_cls: MagicMock) -> None:
        """Tags like '2.0.0' (no 'v' prefix) work correctly."""
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.data = self._make_release_json("2.0.0")
        mock_pool_cls.return_value.request.return_value = mock_resp

        result = check_for_update()
        assert result is not None
        assert result.version == "2.0.0"

    @patch("calmweb.updater.urllib3.PoolManager")
    @patch("calmweb.updater.__version__", "1.0.0")
    def test_invalid_json_raises(self, mock_pool_cls: MagicMock) -> None:
        """Malformed JSON raises UpdateCheckError."""
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.data = b"NOT VALID JSON"
        mock_pool_cls.return_value.request.return_value = mock_resp

        with pytest.raises(UpdateCheckError, match="Invalid API response"):
            check_for_update()

    @patch("calmweb.updater.urllib3.PoolManager")
    @patch("calmweb.updater.__version__", "1.0.0")
    def test_missing_tag_name_raises(self, mock_pool_cls: MagicMock) -> None:
        """A release with no tag_name raises UpdateCheckError."""
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.data = json.dumps({"body": "notes", "assets": []}).encode("utf-8")
        mock_pool_cls.return_value.request.return_value = mock_resp

        with pytest.raises(UpdateCheckError, match="no version tag"):
            check_for_update()

    @patch("calmweb.updater.urllib3.PoolManager")
    @patch("calmweb.updater.__version__", "1.0.0")
    def test_release_notes_default(self, mock_pool_cls: MagicMock) -> None:
        """Missing 'body' defaults to a fallback message."""
        data = json.dumps(
            {
                "tag_name": "v2.0.0",
                "html_url": "https://github.com/Tontonjo/calmweb/releases/tag/v2.0.0",
                "body": "",
                "assets": [
                    {
                        "name": "CalmWeb_Setup.exe",
                        "browser_download_url": "https://example.com/CalmWeb_Setup.exe",
                        "size": 100,
                    }
                ],
            }
        ).encode("utf-8")

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.data = data
        mock_pool_cls.return_value.request.return_value = mock_resp

        result = check_for_update()
        assert result is not None
        assert result.release_notes == "No release notes available."


class TestDownloadInstaller:
    """Tests for download_installer()."""

    @patch("calmweb.updater.urllib3.PoolManager")
    def test_successful_download(self, mock_pool_cls: MagicMock) -> None:
        """File is downloaded to dest_dir."""
        content = b"fake installer content" * 100
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.headers = {"Content-Length": str(len(content))}
        # Simulate chunked reading: one chunk of data, then empty to signal EOF
        mock_resp.read = MagicMock(side_effect=[content, b""])
        mock_resp.release_conn = MagicMock()
        mock_pool_cls.return_value.request.return_value = mock_resp

        with tempfile.TemporaryDirectory() as tmpdir:
            result = download_installer("https://example.com/setup.exe", dest_dir=tmpdir)
            assert result.exists()
            assert result.name == "CalmWeb_Setup.exe"
            assert result.read_bytes() == content

    @patch("calmweb.updater.urllib3.PoolManager")
    def test_download_with_progress_callback(self, mock_pool_cls: MagicMock) -> None:
        """Progress callback receives (downloaded, total) calls."""
        content = b"x" * 1000
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.headers = {"Content-Length": "1000"}
        mock_resp.read = MagicMock(side_effect=[content, b""])
        mock_resp.release_conn = MagicMock()
        mock_pool_cls.return_value.request.return_value = mock_resp

        progress_calls: list[tuple[int, int]] = []

        def callback(downloaded: int, total: int) -> None:
            progress_calls.append((downloaded, total))

        with tempfile.TemporaryDirectory() as tmpdir:
            download_installer(
                "https://example.com/setup.exe",
                dest_dir=tmpdir,
                progress_callback=callback,
            )

        assert len(progress_calls) > 0
        last_downloaded, total = progress_calls[-1]
        assert last_downloaded == 1000
        assert total == 1000

    @patch("calmweb.updater.urllib3.PoolManager")
    def test_download_http_error(self, mock_pool_cls: MagicMock) -> None:
        """Non-200 response raises UpdateCheckError."""
        mock_resp = MagicMock()
        mock_resp.status = 404
        mock_resp.release_conn = MagicMock()
        mock_pool_cls.return_value.request.return_value = mock_resp

        with pytest.raises(UpdateCheckError, match="HTTP 404"), tempfile.TemporaryDirectory() as tmpdir:
            download_installer("https://example.com/setup.exe", dest_dir=tmpdir)

    @patch("calmweb.updater.urllib3.PoolManager")
    def test_download_network_error(self, mock_pool_cls: MagicMock) -> None:
        """Network exceptions raise UpdateCheckError."""
        mock_pool_cls.return_value.request.side_effect = Exception("timeout")

        with pytest.raises(UpdateCheckError, match="Download failed"), tempfile.TemporaryDirectory() as tmpdir:
            download_installer("https://example.com/setup.exe", dest_dir=tmpdir)

    @patch("calmweb.updater.urllib3.PoolManager")
    def test_download_default_dest_dir(self, mock_pool_cls: MagicMock) -> None:
        """When dest_dir is None, file is saved to tempfile.gettempdir()."""
        content = b"data"
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.headers = {"Content-Length": str(len(content))}
        mock_resp.read = MagicMock(side_effect=[content, b""])
        mock_resp.release_conn = MagicMock()
        mock_pool_cls.return_value.request.return_value = mock_resp

        result = download_installer("https://example.com/setup.exe")
        try:
            assert result.exists()
            assert result.parent == Path(tempfile.gettempdir())
        finally:
            result.unlink(missing_ok=True)

    @patch("calmweb.updater.urllib3.PoolManager")
    def test_release_conn_called_on_success(self, mock_pool_cls: MagicMock) -> None:
        """release_conn() is called even after a successful download."""
        content = b"data"
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.headers = {"Content-Length": str(len(content))}
        mock_resp.read = MagicMock(side_effect=[content, b""])
        mock_resp.release_conn = MagicMock()
        mock_pool_cls.return_value.request.return_value = mock_resp

        with tempfile.TemporaryDirectory() as tmpdir:
            download_installer("https://example.com/setup.exe", dest_dir=tmpdir)

        mock_resp.release_conn.assert_called_once()


class TestUpdateInfo:
    """Tests for the UpdateInfo dataclass."""

    def test_fields(self) -> None:
        """All fields are accessible."""
        info = UpdateInfo(
            version="2.0.0",
            download_url="https://example.com/setup.exe",
            release_notes="Fixed bugs",
            release_page_url="https://github.com/Tontonjo/calmweb/releases/tag/v2.0.0",
            asset_name="CalmWeb_Setup.exe",
            asset_size=5_000_000,
        )
        assert info.version == "2.0.0"
        assert info.download_url == "https://example.com/setup.exe"
        assert info.release_notes == "Fixed bugs"
        assert info.release_page_url == "https://github.com/Tontonjo/calmweb/releases/tag/v2.0.0"
        assert info.asset_name == "CalmWeb_Setup.exe"
        assert info.asset_size == 5_000_000

    def test_equality(self) -> None:
        """Dataclass equality works by field values."""
        a = UpdateInfo("2.0.0", "url", "notes", "page", "name", 100)
        b = UpdateInfo("2.0.0", "url", "notes", "page", "name", 100)
        assert a == b

    def test_inequality(self) -> None:
        """Different field values produce inequality."""
        a = UpdateInfo("2.0.0", "url", "notes", "page", "name", 100)
        b = UpdateInfo("3.0.0", "url", "notes", "page", "name", 100)
        assert a != b


class TestApplyUpdate:
    """The handover to the update installer.

    ``CloseApplications=force`` in the Inno Setup script means Setup
    terminates CalmWeb as soon as it starts, so the system proxy has to be
    gone *before* the installer is launched, not after.
    """

    @staticmethod
    def _fake_tray(calls: list[str]) -> types.ModuleType:
        """A stand-in for ``calmweb.tray``.

        The real module imports pystray, which needs a display, so it cannot
        be imported on a build machine -- and these tests are about call
        order, not about what the tray does.
        """
        module = types.ModuleType("calmweb.tray")
        module.release_system_state = lambda: calls.append("release")  # type: ignore[attr-defined]
        module.restore_system_state = lambda: calls.append("restore")  # type: ignore[attr-defined]
        module.quit_app = lambda: calls.append("quit")  # type: ignore[attr-defined]
        return module

    @staticmethod
    def _installer(tmpdir: str) -> Path:
        path = Path(tmpdir) / "CalmWeb_Setup.exe"
        path.write_bytes(b"stub")
        return path

    def test_missing_installer_raises(self) -> None:
        """A missing file is refused before anything is touched."""
        with (
            tempfile.TemporaryDirectory() as tmpdir,
            pytest.raises(UpdateCheckError, match="not found"),
        ):
            apply_update(Path(tmpdir) / "nope.exe")

    def test_proxy_is_released_before_the_installer_starts(self) -> None:
        """Cleanup first, launch second, quit last."""
        calls: list[str] = []

        with tempfile.TemporaryDirectory() as tmpdir:
            installer = self._installer(tmpdir)
            with (
                patch.dict(sys.modules, {"calmweb.tray": self._fake_tray(calls)}),
                patch("sys.platform", "linux"),
                patch(
                    "subprocess.Popen",
                    side_effect=lambda *a, **k: calls.append("launch"),
                ),
            ):
                apply_update(installer)

        assert calls == ["release", "launch", "quit"]

    def test_proxy_is_restored_when_the_launch_fails(self) -> None:
        """A declined UAC prompt must not leave the machine unfiltered."""
        calls: list[str] = []

        def _boom(*args: object, **kwargs: object) -> None:
            calls.append("launch")
            raise OSError("elevation refused")

        with tempfile.TemporaryDirectory() as tmpdir:
            installer = self._installer(tmpdir)
            with (
                patch.dict(sys.modules, {"calmweb.tray": self._fake_tray(calls)}),
                patch("sys.platform", "linux"),
                patch("subprocess.Popen", side_effect=_boom),
                pytest.raises(UpdateCheckError),
            ):
                apply_update(installer)

        assert calls == ["release", "launch", "restore"]
