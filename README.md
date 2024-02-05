# Go BBS+ Threshold Signature

## Description
This repo serves as the Go implementation for the BBS+ Threshold Signature Algorithm, as discussed in the paper [Non-Interactive Threshold BBS+ From Pseudorandom Correlations](https://eprint.iacr.org/2023/1076.pdf) (Faust, Sebastian, et al., 2023).

The Rust implementation is also available and is the predecessor to this implementation. [LINK](https://hessenbox.tu-darmstadt.de/dl/fiEEnH9zJezsDorYTsBke7XT/.dir)

## Structure
**fhks_bbs_plus** defines the cryptographic material for the BBS+ Threshold Signature. 

**precomputation** provides a simple mock-up implementation of the PCF-PCG Generator, which provides the precomputed materials (Offline-Phase).

**helpers** store the computational functions for the Online-Phase, which ensures Correlation between Partial Signatures and combines them to create BBS+ Signature.

**measurements** and **tests** are demonstrators and benchmarking for the procedure of threshold signing.

## Test
To run the tests, use the following command. 

```
go test -v ./...
```

## Benchmark

```
go run .
```

## Related works
This repository is part of a project researching the use case of Threshold BBS+ in Credential Issuance.

[Threshold-Integrated-AF-GO](https://github.com/perun-network/aries-framework-go): A fork of Hyperledger Aries Framework Go with the integration of Threshold BBS+, see `pkg/client/vcwallet`.

[BBB-Plus-Threshold-Demo](https://github.com/perun-network/threshold-bbs-plus-frontend): A command-line/ graphical demo utilizing the integrated threshold BBS+ in Aries VCWallet. 
