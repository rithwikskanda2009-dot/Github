"""NetBond launcher for double-click / desktop shortcut (runs without a console)."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from netbond.gui import main  # noqa: E402

if __name__ == "__main__":
    main()
