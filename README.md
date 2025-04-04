# nilQL
[![npm](https://badge.fury.io/js/nilql.svg)](https://www.npmjs.com/package/@nillion/nilql)
[![ci](https://github.com/nillionnetwork/nilql-ts/actions/workflows/ci.yaml/badge.svg)](https://github.com/nillionnetwork/nilql-ts/actions)
[![coveralls](https://coveralls.io/repos/github/NillionNetwork/nilql-ts/badge.svg?branch=main)](https://coveralls.io/github/NillionNetwork/nilql-ts)

Library for working with encrypted data within nilDB queries and replies.

## Description and Purpose

This library provides cryptographic operations that are compatible with nilDB nodes and clusters, allowing developers to leverage certain privacy-enhancing technologies (PETs) when storing, operating upon, and retrieving data while working with nilDB. The table below summarizes the functionalities available in nilQL.

| Cluster        | Operation | Implementation Details                                            | Supported Types                                   |
|----------------|-----------|-------------------------------------------------------------------|---------------------------------------------------|
| single node    | store     | XSalsa20 stream cipher and Poly1305 MAC                           | 32-bit signed integer; UTF-8 string (<4097 bytes) |
| single node    | match     | deterministic salted hashing via SHA-512                          | 32-bit signed integer; UTF-8 string (<4097 bytes) |
| single node    | sum       | non-deterministic Paillier with 2048-bit primes                   | 32-bit signed integer                             |
| multiple nodes | store     | XOR-based secret sharing                                          | 32-bit signed integer; UTF-8 string (<4097 bytes) |
| multiple nodes | match     | deterministic salted hashing via SHA-512                          | 32-bit signed integer; UTF-8 string (<4097 bytes) |
| multiple nodes | sum       | additive secret sharing (no threshold; prime modulus 2^32 + 15)   | 32-bit signed integer                             |
| multiple nodes | sum       | Shamir's secret sharing (with threshold; prime modulus 2^32 + 15) | 32-bit signed integer                             |

## Package Installation and Usage

The package can be installed using [pnpm](https://pnpm.io/):

```shell
pnpm install
```

The library can be imported in the usual way:

```ts
import { nilql } from "@nillion/nilql";
```

An example demonstrating use of the library is presented below:

```ts
const cluster = {"nodes": [{}, {}]};
const secretKey = await nilql.SecretKey.generate(cluster, {"sum": true});
const plaintext = BigInt(123);
const ciphertext = await nilql.encrypt(secretKey, plaintext);
const decrypted = await nilql.decrypt(secretKey, ciphertext);
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
