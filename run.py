import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from core.engine import run

if __name__ == "__main__":
    run()
