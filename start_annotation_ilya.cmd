@echo off
cd /d "%~dp0"
if exist ".venv\Scripts\python.exe" (
  ".venv\Scripts\python.exe" eval\annotation_ui.py --reviewer ilya --port 8766 --open
) else (
  python eval\annotation_ui.py --reviewer ilya --port 8766 --open
)
pause
