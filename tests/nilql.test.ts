/**
 * Functional and algebraic unit tests for primitives.
 * Test suite containing functional unit tests for the exported primitives,
 * as well as unit tests confirming algebraic relationships among primitives.
 */

import { describe, expect, test } from "vitest";
import { nilql } from "#/nilql";

/**
 * API symbols that should be available to users upon module import.
 */
function apiNilql() {
  return ["SecretKey", "PublicKey", "encrypt", "decrypt"];
}

/**
 * Tests verifying the presence of exports.
 */
describe("namespace", () => {
  test("nilql API has all methods", () => {
    expect(nilql).not.toBeNull();
    const methods = Object.getOwnPropertyNames(nilql);
    expect(methods).toEqual(expect.arrayContaining(apiNilql()));
  });
});

/**
 * Tests verifying that methods return objects (or throw errors) having the expected
 * types.
 */
describe("input ranges and errors", () => {
  test("types SecretKey", async () => {
    const cluster = { nodes: [{}] };
    const secretKey = await nilql.SecretKey.generate(cluster, { match: true });
    expect(secretKey).toBeInstanceOf(Object);
  });

  test("types SecretKey", async () => {
    const cluster = { nodes: [{}] };
    const secretKey = await nilql.SecretKey.generate(cluster, { sum: true });
    expect(secretKey).toBeInstanceOf(Object);
  });

  test("types PublicKey", async () => {
    const cluster = { nodes: [{}] };
    const secretKey = await nilql.SecretKey.generate(cluster, { sum: true });
    const publicKey = await nilql.PublicKey.generate(secretKey);
    expect(publicKey).toBeInstanceOf(Object);
  });

  test("errors SecretKey", async () => {
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

  test("errors PublicKey", async () => {
    const cluster = { nodes: [{}, {}] };
    try {
      const secretKey = await nilql.SecretKey.generate(cluster, { sum: true });
      const publicKey = await nilql.PublicKey.generate(secretKey);
    } catch (e) {
      expect(e).toStrictEqual(
        TypeError("cannot create public key for supplied secret key"),
      );
    }
  });

  test("errors encryption for match operation", async () => {
    const cluster = { nodes: [{}] };
    const secretKey = await nilql.SecretKey.generate(cluster, { match: true });
    const plaintext = "x".repeat(4097);

    try {
      await nilql.encrypt(secretKey, plaintext);
    } catch (e) {
      expect(e).toStrictEqual(
        TypeError(
          "plaintext string must be possible to encode in 4096 bytes or fewer",
        ),
      );
    }
  });

  test("errors encryption for sum operation", async () => {
    const cluster = { nodes: [{}] };
    const secretKey = await nilql.SecretKey.generate(cluster, { sum: true });
    const publicKey = await nilql.PublicKey.generate(secretKey);

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

  test("errors decryption", async () => {
    const cluster = { nodes: [{}] };
    const secretKey = await nilql.SecretKey.generate(cluster, { sum: true });
    const secretKeyAlt = await nilql.SecretKey.generate(cluster, { sum: true });
    const publicKey = await nilql.PublicKey.generate(secretKey);

    const plaintextNumber = 123;
    const ciphertextFromNumber = (await nilql.encrypt(
      publicKey,
      plaintextNumber,
    )) as bigint;

    try {
      await nilql.decrypt(secretKeyAlt, ciphertextFromNumber);
    } catch (e) {
      expect(e).toStrictEqual(
        TypeError("ciphertext cannot be decrypted using supplied secret key"),
      );
    }
  });
});

/**
 * Tests of dumping and loading methods of cryptographic key classes.
 */
describe("dumping and loading of cryptographic keys", () => {
  const clusters = [{ nodes: [{}] }, { nodes: [{}, {}, {}] }];

  for (const cluster of clusters) {
    test("dump and load key for store operation", async () => {
      const secretKey = await nilql.SecretKey.generate(cluster, {
        store: true,
      });

      const secretKeyObject = secretKey.dump();
      const secretKeyLoaded = nilql.SecretKey.load(secretKeyObject);

      const plaintext = "abc";
      const ciphertext = await nilql.encrypt(secretKey, plaintext);
      const decrypted = await nilql.decrypt(secretKeyLoaded, ciphertext);
      expect(plaintext).toEqual(decrypted);
    });

    test("dump and load key for match operation", async () => {
      const secretKey = await nilql.SecretKey.generate(cluster, {
        match: true,
      });

      const secretKeyObject = secretKey.dump();
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

  test("dump and load keys for sum operation with single node", async () => {
    const cluster = { nodes: [{}] };
    const secretKey = await nilql.SecretKey.generate(cluster, { sum: true });
    const publicKey = await nilql.PublicKey.generate(secretKey);

    const secretKeyObject = secretKey.dump();
    const secretKeyLoaded = nilql.SecretKey.load(secretKeyObject);

    const publicKeyObject = publicKey.dump();
    const publicKeyLoaded = nilql.PublicKey.load(publicKeyObject);

    const plaintext = BigInt(123);
    const ciphertext = await nilql.encrypt(publicKeyLoaded, plaintext);
    const decrypted = await nilql.decrypt(secretKeyLoaded, ciphertext);
    expect(plaintext).toEqual(decrypted);
  });

  test("dump and load key for sum operation with multiple nodes", async () => {
    const cluster = { nodes: [{}, {}, {}] };
    const secretKey = await nilql.SecretKey.generate(cluster, { sum: true });

    const secretKeyObject = secretKey.dump();
    const secretKeyLoaded = nilql.SecretKey.load(secretKeyObject);

    const plaintext = BigInt(123);
    const ciphertext = await nilql.encrypt(secretKey, plaintext);
    const decrypted = await nilql.decrypt(secretKeyLoaded, ciphertext);
    expect(plaintext).toEqual(decrypted);
  });
});

/**
 * Representation compatibility/portability tests.
 */
describe("representation", () => {
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
 * Tests of functional properties of primitive operators.
 */
describe("functionalities", () => {
  test("secret key creation for sum operation", async () => {
    const cluster = { nodes: [{}] };
    const s = await nilql.SecretKey.generate(cluster, { sum: true });
    expect(s.material).not.toBeNull();
  });

  test("public key creation for sum operation", async () => {
    const cluster = { nodes: [{}] };
    const s = await nilql.SecretKey.generate(cluster, { sum: true });
    const p = await nilql.PublicKey.generate(s);
    expect(p.material).not.toBeNull();
  });

  test("secret key creation for match operation", async () => {
    const cluster = { nodes: [{}] };
    const s = await nilql.SecretKey.generate(cluster, { match: true });
    expect(s.material).not.toBeNull();
  });

  test("encryption of number for match operation", async () => {
    const cluster = { nodes: [{}] };
    const secretKey = await nilql.SecretKey.generate(cluster, { match: true });

    const plaintextNumber = 123;
    const ciphertextFromNumber = (await nilql.encrypt(
      secretKey,
      plaintextNumber,
    )) as string;
    expect(ciphertextFromNumber.length > 64).toEqual(true);

    const plaintextBigInt = BigInt(123);
    const ciphertextFromBigInt = (await nilql.encrypt(
      secretKey,
      plaintextBigInt,
    )) as string;
    expect(ciphertextFromBigInt.length > 64).toEqual(true);
  });

  test("encryption of string for match operation", async () => {
    const cluster = { nodes: [{}] };
    const secretKey = await nilql.SecretKey.generate(cluster, { match: true });

    const plaintext = "ABC";
    const ciphertext = (await nilql.encrypt(secretKey, plaintext)) as string;
    expect(ciphertext.length > 64).toEqual(true);
  });

  test("encryption for sum operation", async () => {
    const cluster = { nodes: [{}] };
    const secretKey = await nilql.SecretKey.generate(cluster, { sum: true });
    const publicKey = await nilql.PublicKey.generate(secretKey);

    const plaintextNumber = 123;
    const ciphertextFromNumber = (await nilql.encrypt(
      publicKey,
      plaintextNumber,
    )) as bigint;
    expect(ciphertextFromNumber).not.toBeNull();

    const plaintextBigInt = BigInt(123);
    const ciphertextFromBigInt = (await nilql.encrypt(
      publicKey,
      plaintextBigInt,
    )) as bigint;
    expect(ciphertextFromBigInt).not.toBeNull();
  });

  test("decryption for sum operation", async () => {
    const cluster = { nodes: [{}] };
    const secretKey = await nilql.SecretKey.generate(cluster, { sum: true });
    const publicKey = await nilql.PublicKey.generate(secretKey);

    const plaintextNumber = 123;
    const ciphertextFromNumber = (await nilql.encrypt(
      publicKey,
      plaintextNumber,
    )) as bigint;
    const decryptedFromNumber = (await nilql.decrypt(
      secretKey,
      ciphertextFromNumber,
    )) as bigint;
    expect(BigInt(plaintextNumber) === decryptedFromNumber).toEqual(true);

    const plaintextBigInt = BigInt(123);
    const ciphertextFromBigInt = (await nilql.encrypt(
      publicKey,
      plaintextBigInt,
    )) as bigint;
    const decryptedFromBigInt = (await nilql.decrypt(
      secretKey,
      ciphertextFromBigInt,
    )) as bigint;
    expect(plaintextBigInt === decryptedFromBigInt).toEqual(true);
  }, 10000);
});

/**
 * End-to-end workflow tests.
 */
describe("workflows", () => {
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
        const secretKey = await nilql.SecretKey.generate(cluster, {
          sum: true,
        });
        const ciphertext = await nilql.encrypt(secretKey, number);
        const decrypted = await nilql.decrypt(secretKey, ciphertext);
        expect(BigInt(number)).toEqual(BigInt(decrypted));
      }, 10000);
    }
  }

  for (const number of numbers) {
    test(`end-to-end workflow for sum operation: ${number}`, async () => {
      const secretKey = await nilql.SecretKey.generate(
        { nodes: [{}] },
        { sum: true },
      );
      const publicKey = await nilql.PublicKey.generate(secretKey);
      const ciphertext = await nilql.encrypt(publicKey, number);
      const decrypted = await nilql.decrypt(secretKey, ciphertext);
      expect(BigInt(number)).toEqual(BigInt(decrypted));
    });
  }
});
