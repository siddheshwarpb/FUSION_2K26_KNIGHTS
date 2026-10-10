"""Application configuration — loads from environment / .env file."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

try:
    from dotenv import load_dotenv
    _env_file = Path(__file__).resolve().parents[2] / ".env"
    load_dotenv(dotenv_path=_env_file, override=False)
except ImportError:
    pass  # python-dotenv optional; fall back to raw os.environ


@dataclass
class QualysConfig:
    """Qualys platform integration settings.

    All values come from environment variables so that no credentials are
    ever hard-coded or committed to source control.
    """
    platform: str = field(default_factory=lambda: os.getenv("QUALYS_PLATFORM", ""))
    client_id: str = field(default_factory=lambda: os.getenv("QUALYS_CLIENT_ID", ""))
    client_secret: str = field(default_factory=lambda: os.getenv("QUALYS_CLIENT_SECRET", ""))
    qscanner_path: str = field(default_factory=lambda: os.getenv("QUALYS_QSCANNER_PATH", "qscanner"))
    scan_timeout: int = field(default_factory=lambda: int(os.getenv("QUALYS_SCAN_TIMEOUT", "300")))

    def is_configured(self) -> bool:
        """Return True only when real credentials are present."""
        return bool(
            self.platform
            and self.client_id
            and self.client_id != "your-client-id-here"
            and self.client_secret
            and self.client_secret != "your-client-secret-here"
        )

    def base_url(self) -> str:
        """Return the base HTTPS URL for Qualys API calls."""
        host = self.platform
        if host.startswith("https://"):
            host = host[len("https://"):]
        elif host.startswith("http://"):
            host = host[len("http://"):]
        return f"https://{host}"


# Module-level singleton — import this in services
qualys_config = QualysConfig()
