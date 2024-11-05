# nilql

Library for working with encrypted data within NilDB queries and replies.

Package Installation and Usage
------------------------------

The package can be installed using NPM:

```shell
npm install
```

The library can be imported in the usual ways:

```TypeScript
const { nilql } = require('@nillion/nilql');
```

An example demonstrating use of the library is presented below:

```TypeScript
const cluster = {"decentralized": false};
const operations = {"match": false, "sum": true};
const secretKey = await nilql.secretKey(cluster, operations);
const publicKey = await nilql.publicKey(secretKey);
const plaintext = BigInt(123);
const ciphertext = (await nilql.encrypt(publicKey, plaintext) as bigint);
const decrypted = (await nilql.decrypt(secretKey, ciphertext) as bigint);
console.assert(plaintext == decrypted);
```

Testing and Conventions
-----------------------

All unit tests are executed and their coverage measured when using [Jest](https://jestjs.io/) (see `jest.config.js` for configuration details):

```shell
npm test
```

Style conventions are enforced using [ESLint](https://eslint.org/):

```shell
npm run lint
```

Contributions
-------------

In order to contribute to the source code, open an issue or submit a pull request on the GitHub page for this library.

Versioning
----------

The version number format for this library and the changes to the library associated with version number increments conform with [Semantic Versioning 2.0.0](https://semver.org/#semantic-versioning-200).
