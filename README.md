# Aries Threshold BBS+ Wallet Demo

This repository aims to demonstarte a credential swap process between a Holder and multiple Signers following the (t-out-of-n) Threshold Secret Sharing. The Aries framework implementation ensures data authentification and exchange between entities within a distributed ledger. Our implementation of the Aries Agent provides the integration of the BBS+ theshold signature with the Aries Verifiable Credential Wallet. This approach boosts security by preventing any single entity from accessing the complete data. It reduces unauthorized access risks, ensures controlled access, protects privacy, and helps with legal compliance. 

In the demonstration, Alice wants her residence permit to be signed from the Faber foreign instituts. Signer0, Signer1 and Signer2 are members of the Faber institut. Each one of them reserves a partial precomputation and can be contacted to sign the residence permit. Alice will have to contact at least two of them to sign her residence permit, in order to combine the signature and produce a BBS+ signature proof for her residence permit (2-out-of-3 Secret Sharing.) The signed credential can be used in conjunction with the generated public key to verify the eligibility of Alice's residence permit.

## Residence Permit Alice-Faber Demo

This Alice and Faber Demo describes a setting where a residence, Alice, connects with the governmet foreign institut, Faber, and asks the institut to issue her a digital verifiable credential for her residence permit. The protocol differs to the traditional Alice-Faber Demo in that, Faber is realised as a group of goverment agents, and Alice has to connect to at least a threshold number t of them, to get t partial signed credential and produce a valid verifiable credential on her own. The protocol in demo involves the following steps:

1. **The BBS+ Precomputation Generator** produced **precomputations** and a **public key**, binded together within a **collectionID** string.

2. Faber's agents import the precomputations to prepare for signing.

3. Alice imports the public key to verify the signature later.

4. Each Faber's signer create an invitation for Alice to establish **DIDComm** connection.

5. Alices connects with the Faber's signers using their invitations.

6. Alice sets the signing threshold for signing. 

7. Alice chooses a threshold number of signers for creating the partial signatures and initiate the Issue Credential Protocol with them by sending a ```credential-proposal``` message.

8. Faber's signers receive the proposal and send back a ```credential-offer``` to confirm.

9. Alice reconfirm with and request a partial signature with a ```credential-request``` message to each of them.

10. Signers accept the request, sign the attached residence permit and send back through ```issue-credential``` messages.

11. Alice collects all the partial signatures from the ```issue-credential``` messages and create a combined BBS+ verifiable credential of her residence permit.

12. Alice can use the imported public key to verify the validity of her signed residence permit.

## Development

### Aries Threshold Wallet

Aries Threshold Wallet is an integration between the concept of Non-Interactive Threshold BBS+ From Pseudorandom Correlations with the Verifiable Credential Wallet from Hyperledger Aries.

The Non-Interactive Threshold BBS+ From Pseudorandom Correlations Protocol introduces a novel protocol called t-out-of-n threshold BBS+ for issuing anonymous credentials, aiming to reduce risks linked to a single credential issuer. It enables efficient and secure credential creation and demonstration of possession while minimizing communication complexity. Unlike existing schemes, this protocol supports various security thresholds and achieves fast signing speeds with minimal impact on performance.

The Verifiable Credential Wallet in Aries Framework Go implements the interface Universal Wallet specified by W3C, which can be used to manage JSON-LD credentials and related data models. 

### Current state

At this stage, the Demo implemented Alice and Faber's signers as Aries Threshold Wallet objects. They perform peer-to-peer credential exchange using the Aries's issue credential protocol. In the first iteration, we assume that all agents act honestly. 

The Threshold BBS+ implementation being used is realised using a simple mock of Pseudorandom Correlations Generators, which need to be swapped out in future iteration.

The current version of VC Wallet does not fully support the storing of precomputations as signing materials (must provide a public and private key as a signing suite). The precomputation is temporary stored in VCWallet instead as Metadata, which can be retrieved for signing partial signatures. This implementation is still considered acceptable because without most of the precomputations are acquired, the adversary still cannot produce a valid signature.

### Run the Demo

The Demonstration is currently under develop with [Go] 1.20 and a forked [Aries Framework Go] v0.4.6-2.

#### Getting started

Running the aries-threshold-demo requires working Go distribution, see ```go.mod``` for the required version.

```sh
# Clone the repository into a directory of your choice.
git clone https://github.com/perun-network/bbs-plus-threshold-wallet
cd bbs-plus-threshold-wallet

# Compile with.
go build

# Check that the binary works.
./bbs-plus-threshold-wallet
```

#### Setup precomputations.

1. Start the Precomputation Generator to generated the public key and precomputations.

```sh
./bbs-plus-threshold-wallet demo --config generator.yaml
```

2. Start another terminal to run Alice and import the **public key** from the generator. 

```sh
./bbs-plus-threshold-wallet demo --config alice.yaml

# Import public key
> import-pk <colletionID>
```
```shell
Encrypted public key: > # public key string
# Example public key string: lI6Kuz10UKkwTUUnv7AzYapMy5Vg+23779nhexXQmOB7cq+bgbTelS3Rp33l3zUBFc/oyH/vW0sBEvESwjRY1iAuquVlS2BumhCsvGpR/H0ClekJuTeLl7R5eTueW7QJ
```

3. Start 3 other terminals, each to run the respective Faber's signers. At each terminal, use the command `import-precomp` to import the precomputation for the respective signer.

```sh
./bbs-plus-threshold-wallet demo --config faber_signer0.yaml
```
```sh
./bbs-plus-threshold-wallet demo --config faber_signer1.yaml
```
```sh
./bbs-plus-threshold-wallet demo --config faber_signer2.yaml
```
```shell
# Import precomputation
> import-precomp <colletionID>

Encrypted precomputation: > # precomputation string
# Example precomputation string: AgAAAAAAAABBUZIzM7/Bo3MbLvMJTCdOxAK4KOcqMK0cSylAvfXRsJSOirs9dFCpME1FJ7+wM2GqTMuVYPtt++/....
```

#### Threshold Credential Issuance Protocol 

4.  Each signer can generate an invitation for alice.
```sh
> invite alice
```
```sh
# Example invitation:
Invitation: 
{
    "serviceEndpoint": "http://localhost:26604",
    "recipientKeys": [
        "did:key:z6MksQJfwkEGpvxeTHanLPkGAbUXimmHtfPv8b5zu9btBDE2"
    ],
    "@id": "fadd56d0-c9d0-4868-9416-7c892f600d27",
    "label": "faber_carl want to connect with alice",
    "@type": "https://didcomm.org/didexchange/1.0/invitation"
}
```

5. Alice can input the invitation of each signer to connect with them with the command `connect`.
```sh
# Example
> connect faber_signer1 did:collection:urn:uuid:77b7dd83-0224-+
```
```sh
Invite details: > # Invitation
```

6. Alice set the threshold based on the what the generator specified.

```sh
> set-threshold #collectionID #threshold
# Example: set-threshold did:collection:urn:uuid:77b7dd83-0224-4ad0-a043-2148f3190320 2
```

7. Alice can propose her residence permit to be signed by the signers.

```sh
> sign residence_permit.json #collectionID #next-index (first = 0)
# Example: sign residence_permit.json did:collection:urn:uuid:77b7dd83-0224-4ad0-a043-2148f3190320 0
```

8. A threshold number of signers will receive the proposal and need follow the Issue Credential Protocol.

```sh
🔁 Incoming credential proposal. Accept(y/n)? 
> y
Sent back offer to holder.
```

```sh
🔁 Incoming credential request. Accept(y/n)? 
> y
Sent back partial signed credential to holder.
```

9. After received all the partial signed credential, Alice combine a valid BBS+ signature and signed the residence permit. Alice stores the signed credential in her digital wallet.

```sh
🔁 Incoming partial signed credential. Accept and combine with other partial signatures. 
INFO[2206] Holder gets the signed credential:           
# Signed Credential

Signed Credential did:credential:urn:uuid:b8d89593-c7de-4aa6-a126-89879367c76e stored in the wallet.
```

10. Alice can then verify the signed credential using the public key she got from the generator.

```sh
> verify #collectionID #signedDocID #publickeyID

# Example verification.
verify did:collection:urn:uuid:77b7dd83-0224-4ad0-a043-2148f3190320 did:credential:urn:uuid:b8d89593-c7de-4aa6-a126-89879367c76e did:public_key:urn:uuid:46f71e02-ce44-495a-baca-e0ff76a835da 

Retrieve signed document                     

Retrieve public key                          

✅ Credential verified.      
```

11. Exit the CLI with command.

```sh
> exit
```

You can always check the current status with command ```info``` and check possible commands with command ```help```.

[Go]: https://go.dev#
[Aries Framework Go]:https://github.com/perun-network/aries-framework-go