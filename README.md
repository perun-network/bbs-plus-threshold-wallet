# Threshold BBS+ from Pseudorandom Correlations Implementation

## Description

This repository serves as the Go implementation for the BBS+ Threshold Signature Algorithm, as proposed in the paper [Non-Interactive Threshold BBS+ From Pseudorandom Correlations](https://eprint.iacr.org/2023/1076.pdf) (Faust et al., 2023).

It contains three main components of a BBS+ Threshold signature generation protocol. Firstly, the precomputation phase, which is the distribution and generation of precomputed shares. Secondly, the online phase, which uses the aforementioned precomputed shares to generate and verify BBS+ signatures.


The online phase of the signing protocol is based on the Rust implementation [here](https://github.com/AppliedCryptoGroup/NI-Threshold-BBS-Plus-Code). It is also published [here](https://github.com/AppliedCryptoGroup/NI-Threshold-BBS-Plus-Code). The offline phase is based on [this](https://github.com/leandro-ro/Threshold-BBS-Plus-PCG) implementation and is being integrated into this repository with the permission of the original author.

Additionally, this repository includes a Zero Knowledge Proof (zkp) package, allowing users to sign messages without exposing the messages and the respective signature. The proof generation and verification protocol is based on [this publication](https://eprint.iacr.org/2016/663.pdf). The implementation itself is functionally equivalent to the Rust implementation [here](https://github.com/mattrglobal/bbs-signatures), and also the Golang code in the [Hyperledger Aries Framework](https://github.com/hyperledger-archives/aries-framework-go/tree/main/pkg/crypto/primitive/bbs12381g2pub).

## Structure
**fhks_bbs_plus** defines the cryptographic material for the BBS+ Threshold Signature. It provides the properties to sign and verify using BBS+ keypairs.

**precomputation** provides a simple mock-up implementation of the PCF-PCG Generator. This is used to compute the necessary components to generate a BBS+ signature (Offline-Phase).

**zkp** provides the Zero-Knowledge Proof implementation for BBS+ signatures. This allows the user to sign messages without revealing the message and the signature, and also proving the knowledge of the legitimate signature.

**helpers** store the computational functions for the Online-Phase, which ensures correlations between Partial Signatures and combines them to generate BBS+ signatures.

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
