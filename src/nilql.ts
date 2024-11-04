/**
 * NilQL: Library for working with encrypted data within NilDB queries and replies.
 */
import * as paillierBigint from 'paillier-bigint';

/**
 * Maximum size of nonnegative numerical plaintext values.
 */
const _PLAINTEXT_MAX = 4294967296;

/**
 * Cluster configuration information.
 */
interface Cluster {
  decentralized: boolean
};

/**
 * Record indicating what operations on ciphertexts are supported.
 */
interface Operations {
  match: boolean,
  sum: boolean
};

/**
 * Data structure for representing all categories of secret key.
 */
interface SecretKey {
  value: {
    publicKey?: object,
    secretSalt?: Uint8Array
  },
  cluster: Cluster,
  operations: Operations
};

/**
 * Data structure for representing all categories of public key.
 */
interface PublicKey {
  value: object,
  cluster: Cluster,
  operations: Operations
};

/**
 * Return a SHA-512 hash of the supplied string.
 */
async function _sha512(bytes: Uint8Array): Promise<Uint8Array> {
  const buffer = await crypto.subtle.digest("SHA-512", bytes);
  return new Uint8Array(buffer);
}

/**
 * Concatenate two Uint8Array instances.
 */
function _concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const c = new Uint8Array(a.length + b.length);
  c.set(a);
  c.set(b, a.length);
  return c;
}

/**
 * Return a new secret key built according to what is specified in the supplied
 * cluster configuration and operation list.
 */
async function secretKey(
  cluster: Cluster = null,
  operations: Operations = {
    match: false,
    sum: false
  }
): Promise<SecretKey>
{
  const instance = {
    value: null,
    cluster: {
      decentralized: false
    },
    operations: {
      match: false,
      sum: false
    }
  };

  if (cluster != null) {
    instance.cluster = cluster;
  }
  if (operations != null) {
    instance.operations = operations;
  }

  // Reject invocation when operations cannot be supported simultaneously.
  if (instance.operations.match && instance.operations.sum) {
    throw new TypeError(
      "cannot create secret key that supports both match and sum operations"
    );
  }

  if (instance.operations.match) {
    const secretSalt = new Uint8Array(64);
    crypto.getRandomValues(secretSalt);
    instance.value = {secretSalt: secretSalt};
  }

  if (instance.operations.sum) {
    const {publicKey, privateKey} = await paillierBigint.generateRandomKeys(2048);
    instance.value = privateKey;
  }

  return instance;
}

/**
 * Return a new public key correponding to the supplied secret key (and
 * according to any information contained therein).
 */
function publicKey(
  secretKey: SecretKey
): PublicKey
{
  const instance = {
    value: null,
    cluster: secretKey.cluster,
    operations: secretKey.operations
  };

  if (secretKey.value.publicKey != null) {
    instance.value = secretKey.value.publicKey;
  } else {
    throw new TypeError("cannot create public key for this secret key");
  }

  return instance;
}

/**
 * Return the ciphertext obtained by encrypting the supplied plaintext
 * using the supplied key.
 */
async function encrypt(
  key: PublicKey | SecretKey,
  plaintext: number | bigint
): Promise<bigint | Uint8Array>
{
  let instance = null;

  // Encrypting (i.e., hashing) a value for matching.
  if ("secretSalt" in key.value && key.operations.match && !key.operations.sum) {
    const secretKey = key as SecretKey;
    let bytes: Buffer = null;

    // Encrypting (i.e., hashing) a `Number` or `BigInt` instance for matching.
    if (typeof plaintext === "number" || typeof plaintext === "bigint") {
      let bigInt = null;
      if (typeof plaintext === "number") {
        bigInt = BigInt(Number(plaintext));
      } else {
        bigInt = plaintext;
      }
      bytes = Buffer.alloc(8);
      bytes.writeBigInt64LE(bigInt as bigint);
    }

    instance = await _sha512(_concat(secretKey.value.secretSalt, bytes));
  }

  // Encrypting a `number` or `bigint` instance for summation.
  if (!key.operations.match && key.operations.sum) {

    // Only non-negative 32-bit integer values are supported.
    if (!(typeof plaintext === "number" || typeof plaintext === "bigint")) {
      throw new TypeError("plaintext must be number or bigint for sum operation");
    }
    if (BigInt(plaintext) < 0 || BigInt(plaintext) >= _PLAINTEXT_MAX) {
      throw new TypeError("plaintext must be 32-bit nonnegative integer value");
    }

    const publicKey = key as PublicKey;
    let paillierPublicKey = (publicKey.value as paillierBigint.PublicKey);
    paillierPublicKey = // Construct again to gain access to methods.
      new paillierBigint.PublicKey(
        BigInt(paillierPublicKey.n),
        BigInt(paillierPublicKey.g)
      );

    let bigInt = null;
    if (typeof plaintext === "number") {
      bigInt = BigInt(Number(plaintext));
    } else {
      bigInt = plaintext;
    }

    instance = paillierPublicKey.encrypt(bigInt as bigint);
  }

  return instance as (bigint | Uint8Array);
}

/**
 * Return the plaintext obtained by decrypting the supplied ciphertext
 * using the supplied secret key.
 */
function decrypt(
  secretKey: SecretKey,
  ciphertext: bigint
): bigint
{
  let instance = null;

  // Decrypting a numerical value that supports summation.
  if (!secretKey.operations.match && secretKey.operations.sum) {
    const paillierPrivateKey = secretKey.value as paillierBigint.PrivateKey;
    instance = paillierPrivateKey.decrypt(ciphertext);

    return instance as bigint;
  }

  throw new TypeError("ciphertext cannot be decrypted using supplied secret key");
}

/**
 * Export overall wrapper class.
 */
export class nilql {
  public static secretKey = secretKey;
  public static publicKey = publicKey;
  public static encrypt = encrypt;
  public static decrypt = decrypt;
}
