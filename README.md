# UHT
Universal-Hacking-Tool

## build
### install pyinstaller:
pip install pyinstaller

### run following command
pyinstaller --onefile ./UHT.py

## (after build)
if you wish to have only the binary, then do:
### These Commands
#### mv dist/UHT.exe .
#### rm UHT.spec
#### rm -r dist
#### rm -r build