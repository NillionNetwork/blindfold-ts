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
    const cluster = {"decentralized": false};
    const s = await nilql.secretKey(cluster, {"match": true, "sum": false});
    expect(s).toBeInstanceOf(Object);
  });

  test('types secretKey', async () => {
    const cluster = {"decentralized": false};
    const s = await nilql.secretKey(cluster, {"match": false, "sum": true});
    expect(s).toBeInstanceOf(Object);
  });

  test('types publicKey', async () => {
    const cluster = {"decentralized": false};
    const s = await nilql.secretKey(cluster, {"match": false, "sum": true});
    const p = await nilql.publicKey(s);
    expect(p).toBeInstanceOf(Object);
  });

  test('errors secretKey', async () => {
    const cluster = {"decentralized": false};
    try {
      const s = await nilql.secretKey(cluster, {"match": true, "sum": true});
    } catch(e) {
      expect(e).toStrictEqual(
        TypeError(
          "cannot create secret key that supports both match and sum operations"
        )
      );
    }
  });

  test('errors publicKey', async () => {
    const cluster = {"decentralized": false};
    const s = await nilql.secretKey(cluster, {"match": true, "sum": false});
    const p = () => nilql.publicKey(s);
    expect(p).toThrow(TypeError);
    expect(p).toThrow("cannot create public key for this secret key");
  });

  test('errors encryption for match operation', async () => {
    const cluster = {"decentralized": false};
    const secretKey = await nilql.secretKey(cluster, {"match": true, "sum": false});
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
    const cluster = {"decentralized": false};
    const secretKey = await nilql.secretKey(cluster, {"match": false, "sum": true});
    const publicKey = await nilql.publicKey(secretKey);

    for (let plaintext of [-123, BigInt(-123), Math.pow(2, 32), BigInt(Math.pow(2, 32))]) {
      try {
        await nilql.encrypt(publicKey, plaintext);
      } catch(e) {
        expect(e).toStrictEqual(
          TypeError("plaintext must be 32-bit nonnegative integer value")
        );
      }
    }
  });

  test('errors decryption', async () => {
    const cluster = {"decentralized": false};
    const secretKey = await nilql.secretKey(cluster, {"match": false, "sum": true});
    const secretKeyAlt = await nilql.secretKey(cluster, {"match": false, "sum": true});
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
 * Tests of functional properties of primitive operators.
 */
describe('functionalities', () => {
  test('secret key creation for sum operation', async () => {
    const cluster = {"decentralized": false};
    const s = await nilql.secretKey(cluster, {"match": false, "sum": true});
    expect(s.value != null).toEqual(true);
  });

  test('public key creation for sum operation', async () => {
    const cluster = {"decentralized": false};
    const s = await nilql.secretKey(cluster, {"match": false, "sum": true});
    const p = await nilql.publicKey(s);
    expect(p.value != null).toEqual(true);
  });

  test('secret key creation for match operation', async () => {
    const cluster = {"decentralized": false};
    const s = await nilql.secretKey(cluster, {"match": true, "sum": false});
    expect(s.value != null).toEqual(true);
  });

  test('encryption of number for match operation', async () => {
    const cluster = {"decentralized": false};
    const secretKey = await nilql.secretKey(cluster, {"match": true, "sum": false});

    const plaintextNumber = 123;
    const ciphertextFromNumber = (await nilql.encrypt(secretKey, plaintextNumber) as Uint8Array);
    expect(ciphertextFromNumber.length == 64).toEqual(true);

    const plaintextBigInt = BigInt(123);
    const ciphertextFromBigInt = (await nilql.encrypt(secretKey, plaintextBigInt) as Uint8Array);
    expect(ciphertextFromBigInt.length == 64).toEqual(true);
  });

  test('encryption of string for match operation', async () => {
    const cluster = {"decentralized": false};
    const secretKey = await nilql.secretKey(cluster, {"match": true, "sum": false});

    const plaintext = "ABC";
    const ciphertext = (await nilql.encrypt(secretKey, plaintext) as Uint8Array);
    expect(ciphertext.length == 64).toEqual(true);
  });

  test('encryption for sum operation', async () => {
    const cluster = {"decentralized": false};
    const secretKey = await nilql.secretKey(cluster, {"match": false, "sum": true});
    const publicKey = await nilql.publicKey(secretKey);

    const plaintextNumber = 123;
    const ciphertextFromNumber = (await nilql.encrypt(publicKey, plaintextNumber) as BigInt);
    expect(ciphertextFromNumber != null).toEqual(true);

    const plaintextBigInt = BigInt(123);
    const ciphertextFromBigInt = (await nilql.encrypt(publicKey, plaintextBigInt) as BigInt);
    expect(ciphertextFromBigInt != null).toEqual(true);
  });

  test('decryption for sum operation', async () => {
    const cluster = {"decentralized": false};
    const secretKey = await nilql.secretKey(cluster, {"match": false, "sum": true});
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
