# Packer
PoC executable packer using resources

## How to Compile
1. Build PackerStub.exe using packerstub.c
2. Build resource file with rsrc.c
3. Build Packer.exe using packer.c and rsrc.c with PackerStub in the same folder

Note: Advised to use MinGW since MSVC++ somehow fails the RunPE method.

## How to Use
1. Launch Windows command shell
2. Usage: Packer.exe [PAYLOAD EXE] [OUTPUT FILE]

Note: PackerStub.exe is only required for compilation.
