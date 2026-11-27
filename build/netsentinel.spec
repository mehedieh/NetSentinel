# PyInstaller spec — portable single-file Windows executable.
# Build:  powershell -ExecutionPolicy Bypass -File build\build.ps1
# The exe runs WITHOUT administrator rights by default (least privilege);
# users can choose "Restart as Administrator" inside the app for admin-only features.
import os
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

ROOT = os.path.abspath(os.path.join(SPECPATH, ".."))

datas = collect_data_files("customtkinter")
datas += [(os.path.join(ROOT, "assets"), "assets"), (os.path.join(ROOT, "config"), "config")]
hidden = collect_submodules("core") + collect_submodules("gui") + collect_submodules("utils") + \
         collect_submodules("database") + ["matplotlib.backends.backend_tkagg"]
try:
    import scapy  # noqa: F401  optional packet capture
    hidden += collect_submodules("scapy.layers") + ["scapy.arch.windows"]
except ImportError:
    pass

a = Analysis([os.path.join(ROOT, "main.py")], pathex=[ROOT], datas=datas, hiddenimports=hidden,
             excludes=["pytest", "tests", "IPython", "PyQt5", "PySide6"], noarchive=False)
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, a.binaries, a.datas, [],
          name="NetSentinel", icon=os.path.join(ROOT, "assets", "netsentinel.ico"),
          console=False, uac_admin=False, upx=False,
          version=None, disable_windowed_traceback=False)
