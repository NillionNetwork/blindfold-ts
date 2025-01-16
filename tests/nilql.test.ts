/**
 * Functional and algebraic unit tests for primitives.
 * Test suite containing functional unit tests for the exported primitives,
 * as well as unit tests confirming algebraic relationships among primitives.
 */

import { describe, expect, test } from "vitest";
import { nilql } from "#/nilql";

/**
 * Helper function for converting an object that may contain `bigint` values
 * to JSON.
 */
function toJSON(o: object) {
  return JSON.stringify(o, (_, v) =>
    typeof v === "bigint" ? v.toString() : v,
  );
}

/**
 * Helper function to compare two arrays of object keys (i.e., strings).
 */
function equalKeys(a: Array<string>, b: Array<string>) {
  const zip = (a: Array<string>, b: Array<string>) =>
    a.map((k, i) => [k, b[i]]);
  return zip(a, b).every((pair) => pair[0] === pair[1]);
}

/**
 * API symbols that should be available to users upon module import.
 */
function apiNilql() {
  return ["SecretKey", "PublicKey", "encrypt", "decrypt", "allot", "unify"];
}

/**
 * Test that the exported classes and functions match the expected API.
 */
describe("namespace", () => {
  test("nilql API has all methods", () => {
    expect(nilql).not.toBeNull();
    const methods = Object.getOwnPropertyNames(nilql);
    expect(methods).toEqual(expect.arrayContaining(apiNilql()));
  });
});

/**
 * Precomputed constant that can be reused to reduce running time of tests.
 */
const secretKeyForSumWithOneNode = await nilql.SecretKey.generate(
  { nodes: [{}] },
  { sum: true },
);

/**
 * Tests of methods of cryptographic key classes.
 */
describe("methods of cryptographic key classes", () => {
  const clusters = [{ nodes: [{}] }, { nodes: [{}, {}, {}] }];
  for (const cluster of clusters) {
    test("generate, dump, JSONify, and load key for store operation", async () => {
      const secretKey = await nilql.SecretKey.generate(cluster, {
        store: true,
      });

      const secretKeyObject = JSON.parse(JSON.stringify(secretKey.dump()));
      const secretKeyLoaded = nilql.SecretKey.load(secretKeyObject);

      const plaintext = "abc";
      const ciphertext = await nilql.encrypt(secretKey, plaintext);
      const decrypted = await nilql.decrypt(secretKeyLoaded, ciphertext);
      expect(plaintext).toEqual(decrypted);
    });

    test("generate, dump, JSONify, and load key for match operation", async () => {
      const secretKey = await nilql.SecretKey.generate(cluster, {
        match: true,
      });

      const secretKeyObject = JSON.parse(JSON.stringify(secretKey.dump()));
      const secretKeyLoaded = nilql.SecretKey.load(secretKeyObject);

      const plaintext = "abc";
      const ciphertext = await nilql.encrypt(secretKey, plaintext);
      const ciphertextViaLoaded = await nilql.encrypt(
        secretKeyLoaded,
        plaintext,
      );
      expect(ciphertextViaLoaded).toEqual(ciphertext);
    });
  }

  test("generate, dump, JSONify, and load keys for sum operation with single node", async () => {
    const cluster = { nodes: [{}] };
    const secretKey = secretKeyForSumWithOneNode;
    const publicKey = await nilql.PublicKey.generate(secretKey);

    const secretKeyObject = JSON.parse(JSON.stringify(secretKey.dump()));
    const secretKeyLoaded = nilql.SecretKey.load(secretKeyObject);

    const publicKeyObject = JSON.parse(JSON.stringify(publicKey.dump()));
    const publicKeyLoaded = nilql.PublicKey.load(publicKeyObject);

    const plaintext = BigInt(123);
    const ciphertext = await nilql.encrypt(publicKeyLoaded, plaintext);
    const decrypted = await nilql.decrypt(secretKeyLoaded, ciphertext);
    expect(plaintext).toEqual(decrypted);
  });

  test("generate, dump, JSONify, and load key for sum operation with multiple nodes", async () => {
    const cluster = { nodes: [{}, {}, {}] };
    const secretKey = await nilql.SecretKey.generate(cluster, { sum: true });

    const secretKeyObject = JSON.parse(JSON.stringify(secretKey.dump()));
    const secretKeyLoaded = nilql.SecretKey.load(secretKeyObject);

    const plaintext = BigInt(123);
    const ciphertext = await nilql.encrypt(secretKey, plaintext);
    const decrypted = await nilql.decrypt(secretKeyLoaded, ciphertext);
    expect(plaintext).toEqual(decrypted);
  });
});

/**
 * Tests of errors thrown by methods of cryptographic key classes.
 */
describe("errors involving methods of cryptographic key classes", () => {
  test("errors in secret key generation", async () => {
    try {
      const secretKey = await nilql.SecretKey.generate(null, null);
    } catch (e) {
      expect(e).toStrictEqual(
        TypeError("valid cluster configuration is required"),
      );
    }

    try {
      const secretKey = await nilql.SecretKey.generate({ nodes: [] }, null);
    } catch (e) {
      expect(e).toStrictEqual(
        TypeError("cluster configuration must contain at least one node"),
      );
    }

    try {
      const secretKey = await nilql.SecretKey.generate({ nodes: [{}] }, null);
    } catch (e) {
      expect(e).toStrictEqual(
        TypeError("valid operations specification is required"),
      );
    }

    try {
      const secretKey = await nilql.SecretKey.generate(
        { nodes: [{}] },
        { match: true, sum: true },
      );
    } catch (e) {
      expect(e).toStrictEqual(
        TypeError("secret key must enable exactly one operation"),
      );
    }
  });

  test("errors in secret key dumping and loading", async () => {
    try {
      const secretKey = await nilql.SecretKey.generate(
        { nodes: [{}, {}, {}] },
        { sum: true },
      );
      const secretKeyObject = secretKey.dump() as {
        material: object;
        cluster: object;
        operations?: object;
      };
      nilql.SecretKey.load({
        material: secretKeyObject.material,
        cluster: secretKeyObject.cluster,
      });
    } catch (e) {
      expect(e).toStrictEqual(
        TypeError("invalid object representation of a secret key"),
      );
    }

    try {
      const secretKey = secretKeyForSumWithOneNode;
      const secretKeyObject = secretKey.dump() as {
        material: {
          l: object;
          m: object;
          n?: object;
          g: object;
        };
        cluster: object;
        operations: object;
      };
      secretKeyObject.material.n = undefined;
      nilql.SecretKey.load({
        material: {
          m: secretKeyObject.material.m,
          l: secretKeyObject.material.l,
        },
        cluster: secretKeyObject.cluster,
        operations: secretKeyObject.operations,
      });
    } catch (e) {
      expect(e).toStrictEqual(
        TypeError("invalid object representation of a secret key"),
      );
    }

    try {
      const secretKey = secretKeyForSumWithOneNode;
      const secretKeyObject = secretKey.dump() as {
        material: {
          l: object;
          m: object | number;
          n: object;
          g: object;
        };
        cluster: object;
        operations: object;
      };
      secretKeyObject.material.m = 123;
      nilql.SecretKey.load(secretKeyObject);
    } catch (e) {
      expect(e).toStrictEqual(
        TypeError("invalid object representation of a secret key"),
      );
    }

    try {
      const secretKey = secretKeyForSumWithOneNode;
      const secretKeyObject = secretKey.dump() as {
        material: {
          l: object;
          m: object;
          n: string | number;
          g: object;
        };
        cluster: object;
        operations: object;
      };
      secretKeyObject.material.n = 123;
      nilql.SecretKey.load(secretKeyObject);
    } catch (e) {
      expect(e).toStrictEqual(
        TypeError("invalid object representation of a secret key"),
      );
    }
  });

  test("errors in public key generation", async () => {
    const cluster = { nodes: [{}, {}, {}] };
    try {
      const secretKey = await nilql.SecretKey.generate(cluster, { sum: true });
      const publicKey = await nilql.PublicKey.generate(secretKey);
    } catch (e) {
      expect(e).toStrictEqual(
        TypeError("cannot create public key for supplied secret key"),
      );
    }
  });

  test("errors in public key dumping and loading", async () => {
    const secretKey = secretKeyForSumWithOneNode;
    const publicKey = await nilql.PublicKey.generate(secretKey);

    try {
      const publicKeyObject = publicKey.dump() as {
        material: { n: string; g: string };
        cluster?: object;
        operations: object;
      };
      nilql.PublicKey.load({
        material: publicKeyObject.material,
        operations: publicKeyObject.operations,
      });
    } catch (e) {
      expect(e).toStrictEqual(
        TypeError("invalid object representation of a public key"),
      );
    }

    try {
      const publicKeyObject = publicKey.dump() as {
        material: { n?: string; g: string };
        cluster: object;
        operations: object;
      };
      nilql.PublicKey.load({
        material: { g: publicKeyObject.material.g },
        cluster: publicKeyObject.cluster,
        operations: publicKeyObject.operations,
      });
    } catch (e) {
      expect(e).toStrictEqual(
        TypeError("invalid object representation of a public key"),
      );
    }

    try {
      const publicKeyObject = publicKey.dump() as {
        material: { n: string; g: string | number };
        cluster: object;
        operations: object;
      };
      publicKeyObject.material.g = 123;
      nilql.PublicKey.load(publicKeyObject);
    } catch (e) {
      expect(e).toStrictEqual(
        TypeError("invalid object representation of a public key"),
      );
    }
  });
});

/**
 * Tests of the functional and algebraic properties of encryption/decryption functions.
 */
describe("encryption and decryption functions", () => {
  const clusters = [{ nodes: [{}] }, { nodes: [{}, {}, {}] }];
  for (const cluster of clusters) {
    test(`encryption and decryption for store operation (${cluster.nodes.length})`, async () => {
      const secretKey = await nilql.SecretKey.generate(cluster, {
        store: true,
      });

      const plaintextNumber = 123;
      const ciphertextFromNumber = await nilql.encrypt(
        secretKey,
        plaintextNumber,
      );
      const decryptedFromNumber = Number(
        await nilql.decrypt(secretKey, ciphertextFromNumber),
      );
      expect(plaintextNumber).toEqual(decryptedFromNumber);

      const plaintextBigInt = BigInt(123);
      const ciphertextFromBigInt = await nilql.encrypt(
        secretKey,
        plaintextBigInt,
      );
      const decryptedFromBigInt = (await nilql.decrypt(
        secretKey,
        ciphertextFromBigInt,
      )) as bigint;
      expect(plaintextBigInt).toEqual(decryptedFromBigInt);

      const plaintextString = "abc";
      const ciphertextFromString = await nilql.encrypt(
        secretKey,
        plaintextString,
      );
      const decryptedFromString = (await nilql.decrypt(
        secretKey,
        ciphertextFromString,
      )) as string;
      expect(plaintextString).toEqual(decryptedFromString);
    });

    test(`encryption of number for match operation (${cluster.nodes.length})`, async () => {
      const secretKey = await nilql.SecretKey.generate(cluster, {
        match: true,
      });

      const plaintextNumber = 123;
      const ciphertextFromNumber = (await nilql.encrypt(
        secretKey,
        plaintextNumber,
      )) as string;

      const plaintextBigInt = BigInt(123);
      const ciphertextFromBigInt = (await nilql.encrypt(
        secretKey,
        plaintextBigInt,
      )) as string;

      expect(ciphertextFromNumber).toEqual(ciphertextFromBigInt);
    });

    test("encryption of string for match operation", async () => {
      const secKeyOne = await nilql.SecretKey.generate(cluster, {
        match: true,
      });
      const secKeyTwo = await nilql.SecretKey.generate(cluster, {
        match: true,
      });

      const plaintextOne = "ABC";
      const plaintextTwo = "ABC";
      const plaintextThree = "abc";
      const ciphertextOne = await nilql.encrypt(secKeyOne, plaintextOne);
      const ciphertextTwo = await nilql.encrypt(secKeyOne, plaintextTwo);
      const ciphertextThree = await nilql.encrypt(secKeyOne, plaintextThree);
      const ciphertextFour = await nilql.encrypt(secKeyTwo, plaintextThree);
      expect(ciphertextOne).toEqual(ciphertextTwo);
      expect(ciphertextOne).not.toEqual(ciphertextThree);
      expect(ciphertextThree).not.toEqual(ciphertextFour);
    });
  }

  test("encryption and decryption for sum operation with single node", async () => {
    const cluster = { nodes: [{}] };
    const secretKey = secretKeyForSumWithOneNode;
    const publicKey = await nilql.PublicKey.generate(secretKey);

    const plaintextNumber = 123;
    const ciphertextFromNumber = await nilql.encrypt(
      publicKey,
      plaintextNumber,
    );
    const decryptedFromNumber = await nilql.decrypt(
      secretKey,
      ciphertextFromNumber,
    );
    expect(BigInt(plaintextNumber)).toEqual(decryptedFromNumber);

    const plaintextBigInt = BigInt(123);
    const ciphertextFromBigInt = await nilql.encrypt(
      publicKey,
      plaintextBigInt,
    );
    const decryptedFromBigInt = await nilql.decrypt(
      secretKey,
      ciphertextFromBigInt,
    );
    expect(plaintextBigInt).toEqual(decryptedFromBigInt);
  });

  test("encryption and decryption for sum operation with multiple nodes", async () => {
    const secretKey = await nilql.SecretKey.generate(
      { nodes: [{}, {}, {}] },
      { sum: true },
    );

    const plaintextNumber = 123;
    const ciphertextFromNumber = await nilql.encrypt(
      secretKey,
      plaintextNumber,
    );
    const decryptedFromNumber = await nilql.decrypt(
      secretKey,
      ciphertextFromNumber,
    );
    expect(BigInt(plaintextNumber)).toEqual(decryptedFromNumber);

    const plaintextBigInt = BigInt(123);
    const ciphertextFromBigInt = await nilql.encrypt(
      secretKey,
      plaintextBigInt,
    );
    const decryptedFromBigInt = await nilql.decrypt(
      secretKey,
      ciphertextFromBigInt,
    );
    expect(plaintextBigInt).toEqual(decryptedFromBigInt);
  });
});

/**
 * Tests of the portable representation of ciphertexts.
 */
describe("portable representation of ciphertexts", () => {
  test("secret share representation for store operation with multiple nodes", async () => {
    const cluster = { nodes: [{}, {}, {}] };
    const secretKey = await nilql.SecretKey.generate(cluster, { store: true });
    const plaintext = "abc";
    const ciphertext = ["Ifkz2Q==", "8nqHOQ==", "0uLWgw=="];
    const decrypted = await nilql.decrypt(secretKey, ciphertext);
    expect(plaintext).toEqual(decrypted);
  });

  test("secret share representation for sum operation with multiple nodes", async () => {
    const cluster = { nodes: [{}, {}, {}] };
    const secretKey = await nilql.SecretKey.generate(cluster, { sum: true });
    const plaintext = BigInt(123);
    const ciphertext = [456, 246, 4294967296 - 123 - 456];
    const decrypted = await nilql.decrypt(secretKey, ciphertext);
    expect(plaintext).toEqual(decrypted);
  });
});

/**
 * Tests verifying that encryption/decryption methods return expected errors.
 */
describe("errors involving encryption and decryption functions", () => {
  test("errors in encryption for store operation", async () => {
    const cluster = { nodes: [{}] };
    const secretKey = await nilql.SecretKey.generate(cluster, { store: true });

    try {
      await nilql.encrypt(secretKey, 2 ** 31 + 1);
    } catch (e) {
      expect(e).toStrictEqual(
        TypeError("numeric plaintext must be a valid 32-bit signed integer"),
      );
    }

    try {
      await nilql.encrypt(secretKey, "x".repeat(4097));
    } catch (e) {
      expect(e).toStrictEqual(
        TypeError(
          "string plaintext must be possible to encode in 4096 bytes or fewer",
        ),
      );
    }
  });

  test("errors in encryption for match operation", async () => {
    const cluster = { nodes: [{}] };
    const secretKey = await nilql.SecretKey.generate(cluster, { match: true });

    try {
      await nilql.encrypt(secretKey, 2 ** 31 + 1);
    } catch (e) {
      expect(e).toStrictEqual(
        TypeError("numeric plaintext must be a valid 32-bit signed integer"),
      );
    }

    try {
      await nilql.encrypt(secretKey, "x".repeat(4097));
    } catch (e) {
      expect(e).toStrictEqual(
        TypeError(
          "string plaintext must be possible to encode in 4096 bytes or fewer",
        ),
      );
    }
  });

  test("errors in encryption for sum operation", async () => {
    const secretKey = secretKeyForSumWithOneNode;
    const publicKey = await nilql.PublicKey.generate(secretKey);

    try {
      await nilql.encrypt(publicKey, "ABC");
    } catch (e) {
      expect(e).toStrictEqual(
        TypeError(
          "plaintext to encrypt for sum operation must be number or bigint",
        ),
      );
    }

    for (const plaintext of [
      -123,
      BigInt(-123),
      (-2) ** 31,
      2 ** 31 - 1,
      -BigInt(2 ** 31),
      BigInt(2 ** 31) - BigInt(1),
    ]) {
      try {
        await nilql.encrypt(publicKey, plaintext);
      } catch (e) {
        expect(e).toStrictEqual(
          TypeError("numeric plaintext must be a valid 32-bit signed integer"),
        );
      }
    }
  });

  test("errors in decryption for store operation due to cluster size mismatch", async () => {
    const secretKeyOne = await nilql.SecretKey.generate(
      { nodes: [{}] },
      { store: true },
    );
    const secretKeyTwo = await nilql.SecretKey.generate(
      { nodes: [{}, {}] },
      { store: true },
    );
    const secretKeyThree = await nilql.SecretKey.generate(
      { nodes: [{}, {}, {}] },
      { store: true },
    );

    const ciphertextOne = await nilql.encrypt(secretKeyOne, 123);
    const ciphertextTwo = await nilql.encrypt(secretKeyTwo, 123);

    try {
      await nilql.decrypt(secretKeyOne, ciphertextTwo);
    } catch (e) {
      expect(e).toStrictEqual(
        TypeError(
          "secret key requires a valid ciphertext from a single-node cluster",
        ),
      );
    }

    try {
      await nilql.decrypt(secretKeyOne, ciphertextOne);
    } catch (e) {
      expect(e).toStrictEqual(
        TypeError(
          "secret key requires a valid ciphertext from a multi-node cluster",
        ),
      );
    }

    try {
      await nilql.decrypt(secretKeyThree, ciphertextTwo);
    } catch (e) {
      expect(e).toStrictEqual(
        TypeError(
          "secret key and ciphertext must have the same associated cluster size",
        ),
      );
    }
  });

  test("errors in decryption for store operation due to key mismatch", async () => {
    const secretKey = await nilql.SecretKey.generate(
      { nodes: [{}] },
      { store: true },
    );
    const secretKeyAlt = await nilql.SecretKey.generate(
      { nodes: [{}] },
      { store: true },
    );
    const ciphertext = await nilql.encrypt(secretKey, 123);

    try {
      await nilql.decrypt(secretKeyAlt, ciphertext);
    } catch (e) {
      expect(e).toStrictEqual(
        TypeError("ciphertext cannot be decrypted using supplied secret key"),
      );
    }
  });

  test("errors in decryption for sum operation  due to key mismatch", async () => {
    const secretKey = secretKeyForSumWithOneNode;
    const secretKeyAlt = await nilql.SecretKey.generate(
      { nodes: [{}] },
      { sum: true },
    );
    const publicKey = await nilql.PublicKey.generate(secretKey);
    const ciphertext = await nilql.encrypt(publicKey, 123);

    try {
      await nilql.decrypt(secretKeyAlt, ciphertext);
    } catch (e) {
      expect(e).toStrictEqual(
        TypeError("ciphertext cannot be decrypted using supplied secret key"),
      );
    }
  });
});

/**
 * Tests involving end-to-end encryption-decryption workflows.
 */
describe("end-to-end workflows", () => {
  const clusters = [{ nodes: [{}] }, { nodes: [{}, {}, {}, {}, {}] }];

  const plaintexts = [
    BigInt((-2) ** 31),
    BigInt(2 ** 31 - 1),
    BigInt(-1),
    BigInt(0),
    BigInt(1),
    BigInt(2),
    BigInt(3),
    "ABC",
    new Array(4095).fill("?").join(""),
  ];

  const numbers = [(-2) ** 31, -1, -3, -1, 0, 1, 3, 2 ** 31 - 1];

  for (const cluster of clusters) {
    for (const plaintext of plaintexts) {
      test("end-to-end workflow for store operation", async () => {
        const secretKey = await nilql.SecretKey.generate(cluster, {
          store: true,
        });
        const ciphertext = await nilql.encrypt(secretKey, plaintext);
        const decrypted = await nilql.decrypt(secretKey, ciphertext);
        expect(plaintext).toEqual(decrypted);
      });

      test("end-to-end workflow for match operation", async () => {
        const secretKey = await nilql.SecretKey.generate(cluster, {
          match: true,
        });
        const ciphertext = await nilql.encrypt(secretKey, plaintext);
        expect(ciphertext).not.toBeNull();
      });
    }

    for (const number of numbers) {
      test(`end-to-end workflow for sum operation: ${number}`, async () => {
        const secretKey =
          cluster.nodes.length === 1
            ? secretKeyForSumWithOneNode
            : await nilql.SecretKey.generate(cluster, {
                sum: true,
              });
        const ciphertext = await nilql.encrypt(secretKey, number);
        const decrypted = await nilql.decrypt(secretKey, ciphertext);
        expect(BigInt(number)).toEqual(BigInt(decrypted));
      });
    }
  }

  for (const number of numbers) {
    test(`end-to-end workflow for sum operation: ${number}`, async () => {
      const secretKey = secretKeyForSumWithOneNode;
      const publicKey = await nilql.PublicKey.generate(secretKey);
      const ciphertext = await nilql.encrypt(publicKey, number);
      const decrypted = await nilql.decrypt(secretKey, ciphertext);
      expect(BigInt(number)).toEqual(BigInt(decrypted));
    });
  }
});

/**
 * Tests involving end-to-end encryption-decryption workflows.
 */
describe("end-to-end workflows involving share allotment and unification", () => {
  const cluster = { nodes: [{}, {}, {}] };

  test("allotment and unification of arrays for a multi-node cluster", async () => {
    const data = [12n, 34n, 56n, 78n, 90n];
    const secretKey = await nilql.SecretKey.generate(cluster, { store: true });
    const encrypted = [];
    for (let i = 0; i < data.length; i++) {
      encrypted.push({ $allot: await nilql.encrypt(secretKey, data[i]) });
    }
    const shares = nilql.allot(encrypted) as Array<Array<object>>;
    expect(shares.length).toEqual(3);
    expect(shares.every((share) => share.length === data.length)).toEqual(true);

    const decrypted = await nilql.unify(secretKey, shares);
    expect(data).toEqual(decrypted);
  });

  test("allotment and unification of simple objects for a multi-node cluster", async () => {
    const data: { [k: string]: bigint } = {
      a: 12n,
      b: 34n,
      c: 56n,
      d: 78n,
      e: 90n,
    };
    const secretKey = await nilql.SecretKey.generate(cluster, { store: true });
    const encrypted: { [k: string]: object } = {};
    for (const key in data) {
      encrypted[key] = { $allot: await nilql.encrypt(secretKey, data[key]) };
    }
    const shares = nilql.allot(encrypted) as Array<Array<object>>;
    expect(shares.length).toEqual(3);

    const keys = Object.keys(data);
    expect(
      shares.every((share) => equalKeys(Object.keys(share), keys)),
    ).toEqual(true);

    const decrypted = await nilql.unify(secretKey, shares);
    expect(data).toEqual(decrypted);
  });

  test("allotment and unification of mixed objects for a multi-node cluster", async () => {
    const data: { [k: string]: [boolean, string, bigint] } = {
      a: [true, "v", 12n],
      b: [false, "w", 34n],
      c: [true, "x", 56n],
      d: [false, "y", 78n],
      e: [true, "z", 90n],
    };
    const secretKey = await nilql.SecretKey.generate(cluster, { store: true });
    const encrypted: { [k: string]: object } = {};
    for (const key in data) {
      encrypted[key] = [
        data[key][0],
        data[key][1],
        { $allot: await nilql.encrypt(secretKey, data[key][2]) },
      ];
    }
    const shares = nilql.allot(encrypted) as Array<Array<object>>;
    expect(shares.length).toEqual(3);

    const decrypted = await nilql.unify(secretKey, shares);
    expect(toJSON(data)).toEqual(toJSON(decrypted));
  });
});
