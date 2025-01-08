/**
 * Functional and algebraic unit tests for primitives.
 * Test suite containing functional unit tests for the exported primitives,
 * as well as unit tests confirming algebraic relationships among primitives.
 */

import { nilql } from '../src/nilql';

/**
 * API symbols that should be available to users upon module import.
 */
function apiNilql() {
  return ["secretKey", "publicKey", "encrypt", "decrypt"];
}

/**
 * Tests verifying the presence of exports.
 */
describe('namespace', () => {
  test('nilql API has all methods', () => {
    expect(nilql).not.toBeNull();
    const methods = Object.getOwnPropertyNames(nilql);
    expect(methods).toEqual(expect.arrayContaining(apiNilql()));
  });
});

/**
 * Tests verifying that methods return objects (or throw errors) having the expected
 * types.
 */
describe('input ranges and errors', () => {
  test('types secretKey', async () => {
    const cluster = {"nodes": [{}]};
    const s = await nilql.secretKey(cluster, {"match": true});
    expect(s).toBeInstanceOf(Object);
  });

  test('types secretKey', async () => {
    const cluster = {"nodes": [{}]};
    const s = await nilql.secretKey(cluster, {"sum": true});
    expect(s).toBeInstanceOf(Object);
  });

  test('types publicKey', async () => {
    const cluster = {"nodes": [{}]};
    const s = await nilql.secretKey(cluster, {"sum": true});
    const p = await nilql.publicKey(s);
    expect(p).toBeInstanceOf(Object);
  });

  test('errors secretKey', async () => {
    try {
      const s = await nilql.secretKey(null, null);
    } catch(e) {
      expect(e).toStrictEqual(
        TypeError("valid cluster configuration is required")
      );
    }

    try {
      const s = await nilql.secretKey({"nodes": []}, null);
    } catch(e) {
      expect(e).toStrictEqual(
        TypeError("cluster configuration must contain at least one node")
      );
    }

    try {
      const s = await nilql.secretKey({"nodes": [{}]}, null);
    } catch(e) {
      expect(e).toStrictEqual(
        TypeError("valid operations specification is required")
      );
    }

    try {
      const s = await nilql.secretKey({"nodes": [{}]}, {"match": true, "sum": true});
    } catch(e) {
      expect(e).toStrictEqual(
        TypeError("secret key must enable exactly one operation")
      );
    }
  });

  test('errors publicKey', async () => {
    const cluster = {"nodes": [{}]};
    const s = await nilql.secretKey(cluster, {"match": true});
    const p = () => nilql.publicKey(s);
    expect(p).toThrow(TypeError);
    expect(p).toThrow("cannot create public key for supplied secret key");
  });

  test('errors encryption for match operation', async () => {
    const cluster = {"nodes": [{}]};
    const secretKey = await nilql.secretKey(cluster, {"match": true});
    const plaintext = "x".repeat(4097);

    try {
      await nilql.encrypt(secretKey, plaintext);
    } catch(e) {
      expect(e).toStrictEqual(
        TypeError("plaintext string must be possible to encode in 4096 bytes or fewer")
      );
    }
  });

  test('errors encryption for sum operation', async () => {
    const cluster = {"nodes": [{}]};
    const secretKey = await nilql.secretKey(cluster, {"sum": true});
    const publicKey = await nilql.publicKey(secretKey);

    for (let plaintext of [
      -123, BigInt(-123),
      -Math.pow(2, 31), Math.pow(2, 31) - 1,
      -BigInt(Math.pow(2, 31)), BigInt(Math.pow(2, 31)) - BigInt(1),
    ]) {
      try {
        await nilql.encrypt(publicKey, plaintext);
      } catch(e) {
        expect(e).toStrictEqual(
          TypeError("numeric plaintext must be a valid 32-bit signed integer")
        );
      }
    }
  });

  test('errors decryption', async () => {
    const cluster = {"nodes": [{}]};
    const secretKey = await nilql.secretKey(cluster, {"sum": true});
    const secretKeyAlt = await nilql.secretKey(cluster, {"sum": true});
    const publicKey = await nilql.publicKey(secretKey);
  
    const plaintextNumber = 123;
    const ciphertextFromNumber = (await nilql.encrypt(publicKey, plaintextNumber) as bigint);

    try {
      await nilql.decrypt(secretKeyAlt, ciphertextFromNumber);
    } catch(e) {
      expect(e).toStrictEqual(
        TypeError("ciphertext cannot be decrypted using supplied secret key")
      );
    }
  });
});

/**
 * Representation compatibility/portability tests.
 */
describe('representation', () => {
  test('secret share representation for store operation', async () => {
    const cluster = {"nodes": [{}, {}, {}]};
    const secretKey = await nilql.secretKey(cluster, {"store": true});
    const plaintext = "abc";
    const ciphertext = ['Ifkz2Q==', '8nqHOQ==', '0uLWgw=='];
    const decrypted = await nilql.decrypt(secretKey, ciphertext);
    expect(plaintext).toEqual(decrypted);
  });
});

/**
 * Tests of functional properties of primitive operators.
 */
describe('functionalities', () => {
  test('secret key creation for sum operation', async () => {
    const cluster = {"nodes": [{}]};
    const s = await nilql.secretKey(cluster, {"sum": true});
    expect(s.value != null).toEqual(true);
  });

  test('public key creation for sum operation', async () => {
    const cluster = {"nodes": [{}]};
    const s = await nilql.secretKey(cluster, {"sum": true});
    const p = await nilql.publicKey(s);
    expect(p.value != null).toEqual(true);
  });

  test('secret key creation for match operation', async () => {
    const cluster = {"nodes": [{}]};
    const s = await nilql.secretKey(cluster, {"match": true});
    expect(s.value != null).toEqual(true);
  });

  test('encryption of number for match operation', async () => {
    const cluster = {"nodes": [{}]};
    const secretKey = await nilql.secretKey(cluster, {"match": true});

    const plaintextNumber = 123;
    const ciphertextFromNumber = (await nilql.encrypt(secretKey, plaintextNumber) as string);
    expect(ciphertextFromNumber.length > 64).toEqual(true);

    const plaintextBigInt = BigInt(123);
    const ciphertextFromBigInt = (await nilql.encrypt(secretKey, plaintextBigInt) as string);
    expect(ciphertextFromBigInt.length > 64).toEqual(true);
  });

  test('encryption of string for match operation', async () => {
    const cluster = {"nodes": [{}]};
    const secretKey = await nilql.secretKey(cluster, {"match": true});

    const plaintext = "ABC";
    const ciphertext = (await nilql.encrypt(secretKey, plaintext) as string);
    expect(ciphertext.length > 64).toEqual(true);
  });

  test('encryption for sum operation', async () => {
    const cluster = {"nodes": [{}]};
    const secretKey = await nilql.secretKey(cluster, {"sum": true});
    const publicKey = await nilql.publicKey(secretKey);

    const plaintextNumber = 123;
    const ciphertextFromNumber = (await nilql.encrypt(publicKey, plaintextNumber) as BigInt);
    expect(ciphertextFromNumber != null).toEqual(true);

    const plaintextBigInt = BigInt(123);
    const ciphertextFromBigInt = (await nilql.encrypt(publicKey, plaintextBigInt) as BigInt);
    expect(ciphertextFromBigInt != null).toEqual(true);
  });

  test('decryption for sum operation', async () => {
    const cluster = {"nodes": [{}]};
    const secretKey = await nilql.secretKey(cluster, {"sum": true});
    const publicKey = await nilql.publicKey(secretKey);

    const plaintextNumber = 123;
    const ciphertextFromNumber = (await nilql.encrypt(publicKey, plaintextNumber) as bigint);
    const decryptedFromNumber = (await nilql.decrypt(secretKey, ciphertextFromNumber) as bigint);
    expect(BigInt(plaintextNumber) === decryptedFromNumber).toEqual(true);

    const plaintextBigInt = BigInt(123);
    const ciphertextFromBigInt = (await nilql.encrypt(publicKey, plaintextBigInt) as bigint);
    const decryptedFromBigInt = (await nilql.decrypt(secretKey, ciphertextFromBigInt) as bigint);
    expect(plaintextBigInt === decryptedFromBigInt).toEqual(true);
  });
});

/**
 * End-to-end workflow tests.
 */
describe('workflows', () => {
  const clusters = [
    {"nodes": [{}]},
    {"nodes": [{}, {}, {}, {}, {}]}
  ];

  const plaintexts = [
    BigInt(-(Math.pow(2, 31))), BigInt(Math.pow(2, 31) - 1),
    BigInt(-1), BigInt(0), BigInt(1), BigInt(2), BigInt(3),
    "ABC", (new Array(4095).fill("?")).join("")
  ];

  const numbers = [-(Math.pow(2, 31)), - 1, -3, -2, -1, 0, 1, 2, 3, Math.pow(2, 31) - 1];

  for (const cluster of clusters) {
    for (const plaintext of plaintexts) {
      test("end-to-end workflow for store operation", async () => {
        const secretKey = await nilql.secretKey(cluster, {"store": true});
        const ciphertext = await nilql.encrypt(secretKey, plaintext);
        const decrypted = await nilql.decrypt(secretKey, ciphertext);
        expect(plaintext).toEqual(decrypted);
      });

      test("end-to-end workflow for match operation", async () => {
        const secretKey = await nilql.secretKey(cluster, {"match": true});
        const ciphertext = await nilql.encrypt(secretKey, plaintext);
        expect(ciphertext != null).toEqual(true);
      });
    }

    for (const number of numbers) {
      test("end-to-end workflow for sum operation: " + number, async () => {
        const secretKey = await nilql.secretKey(cluster, {"sum": true});
        const ciphertext = await nilql.encrypt(secretKey, number);
        const decrypted = await nilql.decrypt(secretKey, ciphertext);
        expect(BigInt(number)).toEqual(BigInt(decrypted));
      });
    }
  }

  for (const number of numbers) {
    test("end-to-end workflow for sum operation: " + number, async () => {
      const secretKey = await nilql.secretKey({"nodes": [{}]}, {"sum": true});
      const publicKey = await nilql.publicKey(secretKey);
      const ciphertext = await nilql.encrypt(publicKey, number);
      const decrypted = await nilql.decrypt(secretKey, ciphertext);
      expect(BigInt(number)).toEqual(BigInt(decrypted));
    });
  }
});
