"""Export the full-server example's OpenAPI schema without starting ASGI."""

import json
import sys
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
EXAMPLE_DIR = ROOT_DIR / "examples" / "full-server"
sys.path.insert(0, str(ROOT_DIR))
sys.path.insert(0, str(EXAMPLE_DIR))

from app.main import create_app  # noqa: E402


def main() -> None:
    """Generate and save the OpenAPI schema."""
    app = create_app()
    schema = app.openapi()

    output = ROOT_DIR / "openapi.json"
    output.write_text(
        json.dumps(schema, indent=2),
        encoding="utf-8",
    )

    print(f"OpenAPI schema written to {output}")


if __name__ == "__main__":
    main()
