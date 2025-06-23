# blindfold-ts

[![npm](https://badge.fury.io/js/blindfold.svg)](https://www.npmjs.com/package/@nillion/blindfold)
[![ci](https://github.com/nillionnetwork/blindfold-ts/actions/workflows/ci.yaml/badge.svg)](https://github.com/nillionnetwork/blindfold-ts/actions)
[![coveralls](https://coveralls.io/repos/github/NillionNetwork/blindfold-ts/badge.svg?branch=main)](https://coveralls.io/github/NillionNetwork/blindfold-ts)

Library for working with encrypted data within nilDB queries and replies.

## Description and Purpose

This library provides cryptographic operations that are compatible with nilDB nodes and clusters, allowing developers to leverage certain privacy-enhancing technologies (PETs) when storing, operating upon, and retrieving data while working with nilDB. The table below summarizes the functionalities available in blindfold.

| Cluster        | Operation | Implementation Details                                            | Supported Types                                   |
|----------------|-----------|-------------------------------------------------------------------|---------------------------------------------------|
| single node    | store     | XSalsa20 stream cipher and Poly1305 MAC                           | 32-bit signed integer; UTF-8 string (<4097 bytes) |
| single node    | match     | deterministic salted hashing via SHA-512                          | 32-bit signed integer; UTF-8 string (<4097 bytes) |
| single node    | sum       | non-deterministic Paillier with 2048-bit primes                   | 32-bit signed integer                             |
| multiple nodes | store     | XOR-based secret sharing                                          | 32-bit signed integer; UTF-8 string (<4097 bytes) |
| multiple nodes | match     | deterministic salted hashing via SHA-512                          | 32-bit signed integer; UTF-8 string (<4097 bytes) |
| multiple nodes | sum       | additive secret sharing (no threshold; prime modulus 2^32 + 15)   | 32-bit signed integer                             |
| multiple nodes | sum       | Shamir's secret sharing (with threshold; prime modulus 2^32 + 15) | 32-bit signed integer                             |

The library supports two categories of keys:

1. `SecretKey`: Keys in this category support operations within a single node or across multiple nodes. These contain cryptographic material for encryption, decryption, and other operations. Notably, a `SecretKey` instance includes blinding masks that a client need not share with the cluster. By using `SecretKey` instances a client can retain exclusive access to its data *even if all servers in a cluster collude*. 

2. `ClusterKey`: Keys in this category represent cluster configurations but do not contain cryptographic material. These can be used only when working with multiple-node clusters. Unlike `SecretKey` instances, `ClusterKey` instances do not incorporate blinding masks. This means each node in a cluster has access to a raw secret share of the encrypted data and, therefore, the data is only protected if the nodes in the cluster do not collude.

Threshold secret sharing is supported when encrypting in a summation-compatible way for multiple-node clusters. A threshold specifies the minimum number of nodes required to reconstruct the original data. Shamir's secret sharing is employed when encrypting with a threshold value, ensuring that encrypted data can only be decrypted if the required number of shares is available.

## Package Installation and Usage

The package can be installed using [pnpm](https://pnpm.io/):

```shell
pnpm install
```

The library can be imported in the usual way:

```ts
import { blindfold } from "@nillion/blindfold";
```

### Example: Generating Keys

The example below generates a `SecretKey` instance for a single-node cluster:

```ts
const cluster = {"nodes": [{}]};
const secretKey = await blindfold.SecretKey.generate(cluster, {"store": true});
```

The example below generates a `SecretKey` instance for a multiple-node (*i.e.*, three-node) cluster with a two-share decryption threshold:

```ts
const cluster = {"nodes": [{}, {}, {}]};
const secretKey = await blindfold.SecretKey.generate(cluster, {"sum": true}, 2);
```

### Example: Encrypting and Decrypting Data

The below example encrypts and decrypts a string:

```ts
const secretKey = await blindfold.SecretKey.generate({"nodes": [{}]}, {"store": true});
const plaintext = "abc";
const ciphertext = await blindfold.encrypt(secretKey, plaintext);
const decrypted = await blindfold.decrypt(secretKey, ciphertext);
console.log(plaintext, decrypted); // Should output `abc abc`.
```

The below example encrypts and decrypts an integer:

```ts
const secretKey = await blindfold.SecretKey.generate({"nodes": [{}, {}, {}]}, {"sum": true}, 2);
const plaintext = BigInt(123);
const ciphertext = await blindfold.encrypt(secretKey, plaintext);
const decrypted = await blindfold.decrypt(secretKey, ciphertext);
console.log(plaintext, decrypted); // Should output `123n 123n`.
```

## Testing and Conventions

All unit tests are executed and their coverage measured with [vitest](https://vitest.dev/):

```shell
pnpm test
```

Style conventions are enforced using [biomejs](https://biomejs.dev/):

```shell
pnpm lint
```

Types are checked with:

```shell
pnpm typecheck
```

The distribution files are checked with:

```shell
pnpm exportscheck
```

## Contributions

In order to contribute, open an issue or submit a pull request on the GitHub. To enforce conventions, git hooks are provided and can be setup with:

```shell
pnpm install-hooks
```

## Versioning

The version number format for this library and the changes to the library associated with version number increments conform with [Semantic Versioning 2.0.0](https://semver.org/#semantic-versioning-200).
