# 🦖 TRex 🦖

TRex is a tool for reconstructing types from binary code.

<img src="./.figures/trex-phases.svg" alt="Phases in TRex" height="400"/>

> [!NOTE]
> This repository contains the core tool implementation.  You may additionally be interested in looking at [the paper](#publications)'s [companion artifact repository](https://github.com/secure-foundations/trex-usenix25), which contains the tooling to evaluate it.

## How to Use

To obtain reconstructed types for a binary, follow these steps:

1. Confirm that the [necessary software requirements](#requirements) are met.
2. Inside the `utils/` directory, run `just pcode-export foo` to obtain basic
   lifted-disassembly (`foo.lifted`) from a stripped binary (`foo.ndbg-bin`).
   * This uses Ghidra to perform disassembly, and lifts to PCode that TRex can
     parse. Additional parsers can be added to TRex to handle lifted code from
     other disassemblers/decompilers (PRs welcome!).
   * More instructions are available in `utils/README.md`
   * NOTE: for simplicity, we identify all input/output files for the various
     steps/tools using unique extensions; in these instructions, `foo` _always_
     refers to the path to a file _without_ the extension. The extension
     `ndbg-bin` refers to a "no debug info, binary", i.e., a stripped
     executable.
3. (Optional) Run `just var-extract foo` within `utils/` to select subset of
   variables to obtain types for.
   * This step simply reduces the amount of output that TRex provides, and make
     it easier to read things with more human-readable names, rather than
     auto-generated names. To keep things human-readable, this step uses the
     non-stripped binary (`foo.binar`) as input in order to get names of
     variables; however, we note that one could also manually write a `foo.vars`
     file (_without_ access to the unstripped binary) to pick a separate subset.
   * If you do not run this step, TRex will automatically restrict its outputs
     to variables that it detects to be function parameters, to reduce the
     firehose of output. Use `--help` to know how to unleash the full firehose
     of _all_ variables.
4. Run `cargo run --release -- from-ghidra foo.lifted foo.vars` inside the `trex/`
   directory to obtain both structural and C-like types.
   * The `from-ghidra` just says "this is Ghidra-based lifted disassembly";
     alternative disassemblers/decompilers would have similar `from-<baz>`
     commands.
   * You can use `cargo run --release -- from-ghidra --help` to discover
     additional options, including many advanced configuration flags under `-Z`.

## Requirements

* [Rust](https://www.rust-lang.org/)
* [Just](https://github.com/casey/just)
* [Ghidra](https://github.com/NationalSecurityAgency/ghidra)
  - Must be installed to `/opt/ghidra`.
  - Running `just ghidra-test` (inside the `utils/` directory) will output "Confirmed" if Ghidra is installed successfully.

<details><summary>Known-working versions (click to expand)</summary>

The following versions of the above requirements have been tested. While we
expect code to work on more recent versions, your mileage may vary.

* Rust: 1.86.0
* Just: 1.40.0
* Ghidra: 10.4
  - **IMPORTANT**: Ghidra will likely require installing a specific version of JDK. Some of the more recent versions of JDK seem to sometimes break Ghidra, thus we recommend using JDK 17. We have tested this version of Ghidra to work successfully with [JDK (17.0.14)](https://www.oracle.com/java/technologies/javase/jdk17-0-13-later-archive-downloads.html). More recent versions of Ghidra may have fixed this issue.

</details>

## Example

For ease of testing, we include a couple of [examples](./trex/tests/) in this
repository that have already had steps 2 and 3 above run, so that you can jump
to the main TRex execution (step 4) directly.

```console
$ cd trex

$ cargo run --release -- from-ghidra tests/test-linked-list-slot2.lifted tests/test-linked-list-slot2.vars
[...truncated...]
// n@getlast@00100000 : t1*
// nxt@getlast@00100000 : t1*

struct t1 {
  int32_t field_0;
  t1* field_8;
};
```

## License

BSD 3-Clause License. See [LICENSE](./LICENSE).

## Publications

[TRex: Practical Type Reconstruction for Binary Code](TODO-link-to-PDF). Jay Bosamiya, Maverick Woo, and Bryan Parno. In Proceedings of the USENIX Security Symposium, August, 2025.

```bibtex
@inproceedings{trex,
  author    = {Bosamiya, Jay and Woo, Maverick and Parno, Bryan},
  booktitle = {Proceedings of the USENIX Security Symposium},
  month     = {August},
  title     = {{TRex}: Practical Type Reconstruction for Binary Code},
  year      = {2025}
}
```
