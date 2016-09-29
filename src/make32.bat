@echo off
echo [*] Making PackerStub.exe
gcc -mwindows -std=c99 -s -o PackerStub.exe packerstub.c quicklz.c rc4.c -lshlwapi
echo [*] Building resources...
windres rsrc.rc -O coff -o resource.res
echo [*] Compiling Packer.exe...
gcc -std=c99 -s -O3 -o ..\bin32\Packer.exe packer.c quicklz.c rc4.c resource.res -lshlwapi
del PackerStub.exe
echo [*] Finished