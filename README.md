# blindfold-ts

[![npm](https://badge.fury.io/js/blindfold.svg)](https://www.npmjs.com/package/@nillion/blindfold)
[![ci](https://github.com/nillionnetwork/blindfold-ts/actions/workflows/ci.yaml/badge.svg)](https://github.com/nillionnetwork/blindfold-ts/actions)
[![coveralls](https://coveralls.io/repos/github/NillionNetwork/blindfold-ts/badge.svg?branch=main)](https://coveralls.io/github/NillionNetwork/blindfold-ts)

Library for working with encrypted data within nilDB queries and replies.
Library for working with encrypted data within [nilDB](https://docs.nillion.com/build/nildb) queries and replies.

## Description and Purpose

This library provides cryptographic operations that are compatible with [nilDB](https://docs.nillion.com/build/nildb) nodes and clusters, allowing developers to leverage certain privacy-enhancing technologies (PETs) when storing, operating upon, and retrieving data while working with nilDB.

## Package Installation and Usage

The package can be installed using [pnpm](https://pnpm.io/):

```shell
pnpm install
```

The library can be imported in the usual way:

```ts
import { blindfold } from "@nillion/blindfold";
```

### Supported Protocols

The table below summarizes the data encryption protocols that this library makes available. The table also specifies which operation involving ciphertexts is supported by each protocol. Note that support for summation of encrypted values implies support both for subtraction of encrypted values from other encrypted values and for multiplication of encrypted values by a plaintext signed integer scalar.

| Cluster        | Operation | Implementation Details                          | Supported Types                                   |
|----------------|-----------|-------------------------------------------------|---------------------------------------------------|
| single node    | store     | XSalsa20 stream cipher and Poly1305 MAC         | 32-bit signed integer; UTF-8 string (<4097 bytes) |
| single node    | match     | deterministic salted hashing via SHA-512        | 32-bit signed integer; UTF-8 string (<4097 bytes) |
| single node    | sum       | non-deterministic Paillier with 2048-bit primes | 32-bit signed integer                             |
| multiple nodes | store     | XOR-based secret sharing                        | 32-bit signed integer; UTF-8 string (<4097 bytes) |
| multiple nodes | store     | Shamir's secret sharing (with threshold)        | 32-bit signed integer; UTF-8 string (<4097 bytes) |
| multiple nodes | match     | deterministic salted hashing via SHA-512        | 32-bit signed integer; UTF-8 string (<4097 bytes) |
| multiple nodes | sum       | additive secret sharing                         | 32-bit signed integer                             |
| multiple nodes | sum       | Shamir's secret sharing (with threshold)        | 32-bit signed integer                             |

### Categories of Encryption Keys

This library uses the attributes of a key object (instantiated using an appropriate constructor) to determine what protocol to use when encrypting a plaintext. Keys fall into one of two categories:

1. `SecretKey`/`PublicKey`: Keys in this category support operations within a single node or across multiple nodes. These contain cryptographic material for encryption, decryption, and other operations. Notably, a `SecretKey` instance includes cryptographic material (such as symmetric keys) that a client should not share with the cluster. Using a `SecretKey` instance helps ensure that a client can retain exclusive access to a plaintext *even if all servers in a cluster collude*.

2. `ClusterKey`: Keys in this category represent cluster configurations but do not contain cryptographic material. These can be used only when working with multiple-node clusters. Unlike `SecretKey` and `PublicKey` instances, `ClusterKey` instances do not incorporate additional cryptographic material. This means each node in a cluster has access to a raw secret share of the plaintext and, therefore, the plaintext is only protected if the nodes in the cluster do not collude.

### More Details on Secret Sharing

When working with multiple-node clusters and encrypting data for compatibility with the store operation using a `SecretKey` instance, each secret share is encrypted using a symmetric key (the material for which is stored inside the `SecretKey` instance). However, when encrypting for compatibility with the sum operation (without or with a threshold), each secret share is instead *masked* via multiplication with a secret nonzero scalar (with one secret scalar per node stored in the `SecretKey` instance). While this ensures that the secret-shared plaintexts encrypted in this way are compatible with addition and scalar multiplication, users should use this feature only if they have a thorough understanding of the privacy and security trade-offs involved.

Threshold secret sharing is supported when encrypting for multiple-node clusters (with the exception of encrypting for compatibility with the match operation). A threshold specifies the minimum number of nodes required to reconstruct the original data. Shamir's secret sharing is employed when encrypting with support for a threshold, ensuring that encrypted data can only be decrypted if the required number of shares is available.

### Ciphertext Overheads

The table below presents tight upper bounds on ciphertext sizes (in bytes) for each supported protocol when it is used to encrypt a plaintext having *k* bytes. For multiple-node protocols, the size of the ciphertext delivered to an individual node is reported (excluding any overheads associated with the container type within which separate ciphertext components such as the share index and value reside). The upper bounds below are checked within the testing script.

| Cluster        | Key Type | Operation         | Implementation Details                              | Approx.   |
|----------------|----------|-------------------|-----------------------------------------------------|-----------|
| single node    | Secret   | store             | 2 + **ceil** [(4/3)(*k* + 41)]                      | (4/3) *k* |
| single node    | Secret   | match             | 88                                                  | 88        |
| single node    | Secret   | sum               | 2048                                                | 2048      |
| multiple nodes | Secret   | store             | 2 + **ceil** [(4/3)(*k* + 41)]                      | (4/3) *k* |
| multiple nodes | Secret   | store (threshold) | 2 + **ceil** [(4/3) **ceil** [(5/4)(*k* + 4) + 45]] | (5/3) *k* |
| multiple nodes | Secret   | match             | 88                                                  | 88        |
| multiple nodes | Secret   | sum               | 4                                                   | 4         |
| multiple nodes | Secret   | sum (threshold)   | 8                                                   | 8         |
| multiple nodes | Cluster  | store             | 2 + **ceil** ((4/3)(k + 1))                         | (4/3) *k* |
| multiple nodes | Cluster  | store (threshold) | 2 + **ceil** [(4/3) **ceil** [(5/4)(*k* + 4) + 5]]  | (5/3) *k* |
| multiple nodes | Cluster  | sum               | 4                                                   | 4         |
| multiple nodes | Cluster  | sum (threshold)   | 8                                                   | 8         |

### Examples

Extensive documentation, examples, and developer tools that can assist anyone interested in using this library are available in the [Nillion Docs on Private Storage with nilDB](https://docs.nillion.com/build/private-storage/overview).

The example below generates a `SecretKey` instance for encrypting data to be stored within a single-node cluster:

```ts
const cluster = {nodes: [{}]};
const secretKey = await blindfold.SecretKey.generate(cluster, {store: true});
```

The example below generates a `ClusterKey` instance for converting data into secret shares (such that summation on secret-shared data is supported) to be stored in a three-node cluster with a two-share decryption threshold:

```ts
const cluster = {nodes: [{}, {}, {}]};
const clusterKey = await blindfold.ClusterKey.generate(cluster, {sum: true}, 2);
```

The below example encrypts and decrypts a string:

```ts
const secretKey = await blindfold.SecretKey.generate({nodes: [{}]}, {store: true});
const plaintext = "abc";
const ciphertext = await blindfold.encrypt(secretKey, plaintext);
const decrypted = await blindfold.decrypt(secretKey, ciphertext);
console.log(plaintext, decrypted); // Should output `abc abc`.
```

The example below generates three secret shares of an integer and then reconstructs that integer using only two of the shares:

```ts
const secretKey = await blindfold.SecretKey.generate({nodes: [{}, {}, {}]}, {sum: true}, 2);
const plaintext = BigInt(123);
const shares = await blindfold.encrypt(secretKey, plaintext);
shares.pop();
const decrypted = await blindfold.decrypt(secretKey, shares);
console.log(plaintext, decrypted); // Should output `123n 123n`.
```

## Development

Use of [pnpm](https://pnpm.io/) is recommended for typical development tasks.

### Testing and Conventions

All unit tests are executed and their coverage measured with [vitest](https://vitest.dev/):

```shell
pnpm test
```

Style conventions are enforced using [biomejs](https://biomejs.dev/):

```shell
pnpm lint
```

Type checking can be performed:

```shell
pnpm typecheck
```

The distribution files can also be checked:

```shell
pnpm exportscheck
```

### Contributions
In order to contribute to the source code, open an issue or submit a pull request on the [GitHub page](https://github.com/nillionnetwork/blindfold-ts) for this library. To enforce conventions, git hooks are provided and can be installed:

```shell
pnpm install-hooks
```

### Versioning

The version number format for this library and the changes to the library associated with version number increments conform with [Semantic Versioning 2.0.0](https://semver.org/#semantic-versioning-200).
