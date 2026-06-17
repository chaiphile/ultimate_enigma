"""Unit tests for builders/app_builder.py."""

from unittest.mock import MagicMock, patch

import pytest

from builders.app_builder import AppBuilder, StartupCancelled


def _patch_builder_dependencies():
    return (
        patch("builders.app_builder.ttk.Style"),
        patch("builders.app_builder.database.init_db"),
        patch("builders.app_builder.KeyStore"),
        patch("builders.app_builder.ApplicationController"),
        patch("builders.app_builder.TotpPersistence"),
        patch("builders.app_builder.AuthController"),
        patch("builders.app_builder.ServiceOrchestrator"),
        patch("builders.app_builder.TrustChainService"),
        patch("builders.app_builder.event_bus"),
        patch("builders.app_builder.tk.PhotoImage"),
    )


class TestAppBuilderStartupCancellation:
    def test_auth_failure_cleans_up_and_raises_startup_cancelled(self, monkeypatch):
        """Failed authentication is an expected startup abort, not a build crash."""
        import database

        root = MagicMock()
        root.after = MagicMock(return_value="after-id")
        monkeypatch.setattr(database, "DB_PATH", MagicMock(exists=MagicMock(return_value=True)))

        patches = _patch_builder_dependencies()
        with patches[0] as mock_style, patches[1], patches[2], \
             patches[3] as mock_app_controller_cls, patches[4], \
             patches[5] as mock_auth_controller_cls, patches[6], patches[7], \
             patches[8], patches[9]:
            mock_style.return_value.colors.bg = "#000"
            mock_style.return_value.colors.fg = "#fff"
            mock_style.return_value.colors.primary = "#0af"
            mock_style.return_value.colors.secondary = "#888"
            mock_style.return_value.colors.dark = "#111"

            app_controller = MagicMock()
            mock_app_controller_cls.return_value = app_controller
            auth_controller = MagicMock()
            auth_controller.load_keys.return_value = False
            mock_auth_controller_cls.return_value = auth_controller

            builder = AppBuilder(root)

            with pytest.raises(StartupCancelled):
                builder.build()

        app_controller.start_queue_processing.assert_called_once()
        app_controller.shutdown.assert_called_once()
        root.destroy.assert_called_once()

    def test_successful_build_returns_components(self, monkeypatch):
        """Successful startup still returns the composed application state."""
        import database

        root = MagicMock()
        monkeypatch.setattr(database, "DB_PATH", MagicMock(exists=MagicMock(return_value=True)))

        patches = _patch_builder_dependencies()
        with patches[0] as mock_style, patches[1], patches[2] as mock_keystore_cls, \
             patches[3] as mock_app_controller_cls, patches[4], \
             patches[5] as mock_auth_controller_cls, \
             patches[6] as mock_orchestrator_cls, patches[7] as mock_trust_cls, \
             patches[8], patches[9]:
            mock_style.return_value.colors.bg = "#000"
            mock_style.return_value.colors.fg = "#fff"
            mock_style.return_value.colors.primary = "#0af"
            mock_style.return_value.colors.secondary = "#888"
            mock_style.return_value.colors.dark = "#111"

            ks = MagicMock()
            mock_keystore_cls.return_value = ks
            app_controller = MagicMock()
            mock_app_controller_cls.return_value = app_controller
            auth_controller = MagicMock()
            auth_controller.load_keys.return_value = True
            auth_controller.enforce_mandatory_totp_setup.return_value = True
            auth_controller.verify_startup_totp.return_value = True
            auth_controller.ks = ks
            mock_auth_controller_cls.return_value = auth_controller
            orchestrator = MagicMock()
            mock_orchestrator_cls.return_value = orchestrator
            trust_service = MagicMock()
            mock_trust_cls.return_value = trust_service

            built = AppBuilder(root).build()

        assert built["ks"] is ks
        assert built["app_controller"] is app_controller
        assert built["service_orchestrator"] is orchestrator
        assert built["trust_chain_service"] is trust_service
        app_controller.shutdown.assert_not_called()
        root.destroy.assert_not_called()
