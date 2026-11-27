import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from utils.paths import set_data_dir  # noqa: E402

set_data_dir(tempfile.mkdtemp(prefix="netsentinel-test-"))
