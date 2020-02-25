# SMArTCAT
SMArTCAT Symbolically Modeled Architecture Timing Channel Analysis Tool

This tool is used to find different types of timing attacks in binaries. As a basis it uses the symbolic execution of angr and a self-composition proof to find any attacks. For more information on the types of timing attacks and the theory behind it see the original paper of Roeland Krak at this [link](https://essay.utwente.nl/72321/1/Krak_MA_EEMCS.pdf).

The difference between the paper and the tool provided here, is that it has been updated to use angr version 8.19.7.25 and the pipelinemodel has been changed to the Sifive Hifive1 rev-B. These modification have been performed by Stefan van den Berg. The modifications made in this project where to use this tool to check the binary from the [NaCl in RISC-V project](https://github.com/stefanberg96/NaCl-RISC-V).

## Usage
There are multiple files with examples, which are the run-files. Next to that there is a manual in place for some extra information.
