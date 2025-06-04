# Utilities

This folder contains helpful utility files, primarily, headless scripts for Ghidra to export information.

To be able to run the Ghidra headless scripts, you require an unzipped version of [a Ghidra release](https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.4_build/ghidra_10.4_PUBLIC_20230928.zip) at `/opt/ghidra`.

You also need [`just`](https://github.com/casey/just) installed to make it easier to run commands, rather than typing long/complex sequences of commands manually.

Expected output:
```console
$ just
Available recipes:
    help             # Print available recipes; run by default if no command specified
    ghidra-test      # Ensure Ghidra exists and works.
    strip-binary foo # Strip `foo.binar` to produce `foo.ndbg-bin`
    pcode-export foo # Export PCode from `foo.ndbg-bin`
    var-extract foo  # Extract variables from `foo.binar`
    
$ just ghidra-test
# Confirming that Ghidra exists and works
# Confirming that it is the version we expect
# Confirmed
```
