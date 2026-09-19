"""Bootstrap installer for Fin-Guardian dependencies.

This is not a setuptools package. It checks whether the required libraries
are importable and installs any that are missing via python -m pip install.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys

PACKAGES = {
    "telethon": "telethon",
    "streamlit": "streamlit",
    "pandas": "pandas",
    "openai": "openai",
    "plotly": "plotly",
    "fpdf": "fpdf2",
    "telegram": "python-telegram-bot",
    "requests": "requests",
    "flask": "flask",
    "flask_cors": "flask-cors",
}


def is_installed(package: str) -> bool:
    return importlib.util.find_spec(package) is not None


def install(packages: list[str]) -> None:
    command = [sys.executable, "-m", "pip", "install", *packages]
    print(f"Installing: {', '.join(packages)}")
    subprocess.check_call(command)


def main() -> None:
    missing_imports = [name for name in PACKAGES if not is_installed(name)]
    if not missing_imports:
        print("All required libraries are already installed.")
        return

    to_install = [PACKAGES[name] for name in missing_imports]
    print(f"Missing libraries: {', '.join(to_install)}")
    install(to_install)

    still_missing = [name for name in PACKAGES if not is_installed(name)]
    if still_missing:
        print(f"Failed to import after install: {', '.join(still_missing)}")
        sys.exit(1)

    print("All required libraries are installed.")


if __name__ == "__main__":
    main()
