@echo off
cd /d "%~dp0"
python setup.py
if errorlevel 1 exit /b 1
python -m streamlit run app.py --server.port 8501
