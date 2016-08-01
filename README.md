# Packer
PoC executable packer using resources

## How to Compile (preferrably with MinGW since MSVC++ somehow fails the RunPE method)
1. Build PackerStub.exe using packerstub.c
2. Build resource file with rsrc.c
3. Build Packer.exe using packer.c and rsrc.c with PackerStub in the same folder

## How to Use
1. Launch Windows command shell
2. Usage: Packer.exe [PAYLOAD EXE] [OUTPUT FILE]

Note: PackerStub.exe is only required for compilation.
