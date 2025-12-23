# blindfold-ts

[![npm](https://badge.fury.io/js/blindfold.svg)](https://www.npmjs.com/package/@nillion/blindfold)
[![ci](https://github.com/nillionnetwork/blindfold-ts/actions/workflows/ci.yaml/badge.svg)](https://github.com/nillionnetwork/blindfold-ts/actions)
[![coveralls](https://coveralls.io/repos/github/NillionNetwork/blindfold-ts/badge.svg?branch=main)](https://coveralls.io/github/NillionNetwork/blindfold-ts)

Library for working with encrypted data within [nilDB](https://docs.nillion.com/build/nildb) queries and replies.

## Purpose

This library provides cryptographic operations that are compatible with [nilDB](https://docs.nillion.com/build/nildb) nodes and clusters, allowing developers to leverage certain privacy-enhancing technologies (PETs) such as [partially homomorphic encryption (PHE)](https://en.wikipedia.org/wiki/Paillier_cryptosystem) and [secure multi-party computation (MPC)](https://en.wikipedia.org/wiki/Secure_multi-party_computation) when storing, operating upon, and retrieving data while working with nilDB.

## Package Installation and Usage

The package can be installed using [pnpm](https://pnpm.io/):

```shell
pnpm install
```

The library can be imported in the usual way:

```ts
import { blindfold } from "@nillion/blindfold";
```

### Categories of Encryption Keys

This library uses the attributes of a key object (instantiated using an appropriate constructor) to determine what protocol to use when encrypting a plaintext. Keys fall into one of two categories:

1. `SecretKey`/`PublicKey`: Keys in this category support operations within a single node or across multiple nodes. These contain cryptographic material for encryption, decryption, and other operations. Notably, a `SecretKey` instance includes cryptographic material (such as symmetric keys) that a client should not share with the cluster. Using a `SecretKey` instance helps ensure that a client can retain exclusive access to a plaintext *even if all servers in a cluster collude*.

2. `ClusterKey`: Keys in this category represent cluster configurations but do not contain cryptographic material. These can be used only when working with multiple-node clusters. Unlike `SecretKey` and `PublicKey` instances, `ClusterKey` instances do not incorporate additional cryptographic material. This means each node in a cluster has access to a raw secret share of the plaintext and, therefore, the plaintext is only protected if the nodes in the cluster do not collude.

### Supported Protocols

The table below summarizes the data encryption protocols that this library makes available (and which a developer may leverage by creating a key object with the appropriate attributes). The table also specifies which operation involving ciphertexts is supported by each protocol. Support for summation of encrypted values implies support both for subtraction of encrypted values from other encrypted values and for multiplication of encrypted values by a plaintext signed integer scalar.

| Cluster        | Key Types                   | Operation | Protocols                                                                                                            | Plaintext Types                                              |
|----------------|-----------------------------|-----------|----------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------|
| single node    | `SecretKey`                 | store     | [XSalsa20 stream cipher and Poly1305 MAC](https://eprint.iacr.org/2011/646)                                          | 32-bit signed integer; UTF-8 text or byte array (4096 bytes) |
| single node    | `SecretKey`                 | match     | [deterministic salted hashing](https://www.sciencedirect.com/science/article/abs/pii/S0306437912001470) with SHA-512 | 32-bit signed integer; UTF-8 text or byte array (4096 bytes) |
| single node    | `SecretKey` and `PublicKey` | sum       | [Paillier cryptosystem](https://en.wikipedia.org/wiki/Paillier_cryptosystem) with 2048-bit primes                    | 32-bit signed integer                                        |
| multiple nodes | `SecretKey` or `ClusterKey` | store     | [XOR secret sharing](https://ieeexplore.ieee.org/document/6769090) (*n*-out-of-*n*)                                  | 32-bit signed integer; UTF-8 text or byte array (4096 bytes) |
| multiple nodes | `SecretKey` or `ClusterKey` | store     | [Shamir's secret sharing](https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing) (threshold)                       | 32-bit signed integer; UTF-8 text or byte array (4096 bytes) |
| multiple nodes | `SecretKey`                 | match     | [deterministic salted hashing](https://www.sciencedirect.com/science/article/abs/pii/S0306437912001470) with SHA-512 | 32-bit signed integer; UTF-8 text or byte array (4096 bytes) |
| multiple nodes | `SecretKey` or `ClusterKey` | sum       | [additive secret sharing](https://link.springer.com/chapter/10.1007/3-540-45539-6_22) (*n*-out-of-*n*)               | 32-bit signed integer                                        |
| multiple nodes | `SecretKey` or `ClusterKey` | sum       | [Shamir's secret sharing](https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing) (threshold)                       | 32-bit signed integer                                        |

### More Details on Secret Sharing

When working with multiple-node clusters and encrypting data for compatibility with the store operation using a `SecretKey` instance, each secret share is encrypted using a symmetric key (the material for which is stored inside the `SecretKey` instance). However, when encrypting for compatibility with the sum operation (without or with a threshold), each secret share is instead *masked* via multiplication with a secret nonzero scalar (with one secret scalar per node stored in the `SecretKey` instance). While this ensures that the secret-shared plaintexts encrypted in this way are compatible with addition and scalar multiplication, users should use this feature only if they have a thorough understanding of the privacy and security trade-offs involved.

Threshold secret sharing is supported when encrypting for multiple-node clusters (with the exception of encrypting for compatibility with the match operation). A threshold specifies the minimum number of nodes required to reconstruct the original data. Shamir's secret sharing is employed when encrypting with support for a threshold, ensuring that encrypted data can be decrypted if the required number of shares is available.

### Ciphertext Overheads

The tables below present tight upper bounds on ciphertext sizes (in bytes) for each supported protocol when it is used to encrypt a plaintext having *k* bytes (where a 32-bit integer plaintext is represented using 4 bytes). For multiple-node protocols appearing in both tables, the size of the ciphertext delivered to an individual node is reported (excluding any overheads associated with the container type within which separate ciphertext components such as the share index and value reside). The upper bounds in both tables are checked within the testing script.

| Cluster        | Key Types                   | Operation              | Exact Upper Bound in Bytes                          | Approximation |
|----------------|-----------------------------|------------------------|-----------------------------------------------------|---------------|
| single node    | `SecretKey`                 | store                  | 2 + **ceil** [(4/3)(*k* + 41)]                      | (4/3) *k*     |
| single node    | `SecretKey`                 | match                  | 88                                                  | 88            |
| single node    | `SecretKey` and `PublicKey` | sum                    | 2048                                                | 2048          |
| multiple nodes | `SecretKey`                 | store (*n*-out-of-*n*) | 2 + **ceil** [(4/3)(*k* + 41)]                      | (4/3) *k*     |
| multiple nodes | `SecretKey`                 | store (threshold)      | 2 + **ceil** [(4/3) **ceil** [(5/4)(*k* + 4) + 45]] | (5/3) *k*     |
| multiple nodes | `SecretKey`                 | match                  | 88                                                  | 88            |
| multiple nodes | `SecretKey`                 | sum (*n*-out-of-*n*)   | 4                                                   | 4             |
| multiple nodes | `SecretKey`                 | sum (threshold)        | 8                                                   | 8             |

The below table lists the upper bounds for ciphertext sizes when encrypting using a `ClusterKey`. The only difference from the corresponding upper bounds when using a `SecretKey` is the absence of a 40-byte overhead (associated with symmetric encryption) when encrypting for storage.

| Cluster        | Key Types                   | Operation              | Exact Upper Bound in Bytes                          | Approximation |
|----------------|-----------------------------|------------------------|-----------------------------------------------------|---------------|
| multiple nodes | `ClusterKey`                | store (*n*-out-of-*n*) | 2 + **ceil** ((4/3)(k + 1))                         | (4/3) *k*     |
| multiple nodes | `ClusterKey`                | store (threshold)      | 2 + **ceil** [(4/3) **ceil** [(5/4)(*k* + 4) + 5]]  | (5/3) *k*     |
| multiple nodes | `ClusterKey`                | sum (*n*-out-of-*n*)   | 4                                                   | 4             |
| multiple nodes | `ClusterKey`                | sum (threshold)        | 8                                                   | 8             |

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
