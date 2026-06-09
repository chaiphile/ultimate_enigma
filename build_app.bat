@echo off
echo Installing PyInstaller...
pip install pyinstaller

echo Building Ultimate Enigma with MCP support...
pyinstaller --onefile --windowed --noconsole --icon=enigma.ico --name="UltimateEnigma" main.py

echo Build complete! Check the 'dist' folder for the executable.
pause
