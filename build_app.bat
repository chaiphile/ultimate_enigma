@echo off
setlocal

set OQS_PATH=C:\Users\Administrator\AppData\Local\Programs\Python\Python312\Lib\site-packages\oqs
set OQS_DLL=C:\Users\Administrator\_oqs\bin\oqs.dll

pip install pyinstaller

echo Building Ultimate Enigma...
pyinstaller --onefile --windowed --noconsole ^
  --icon=enigma.ico ^
  --name="UltimateEnigma" ^
  --add-data "%OQS_PATH%;oqs" ^
  --add-binary "%OQS_DLL%;." ^
  --hidden-import=oqs ^
  main.py

echo Done!
pause