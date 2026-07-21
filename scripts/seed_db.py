import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(PROJECT_ROOT))

from app.database import initialize_database  # noqa: E402

if __name__ == "__main__":
    initialize_database()
    print("Database initialized.")
