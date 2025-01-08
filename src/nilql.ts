/**
 * NilQL: Library for working with encrypted data within NilDB queries and replies.
 */
import * as sodium from 'libsodium-wrappers-sumo';
import * as paillierBigint from 'paillier-bigint';

/**
 * Minimum plaintext 32-bit signed integer value that can be encrypted.
 */
const _PLAINTEXT_SIGNED_INTEGER_MIN = BigInt(-2147483648);

/**
 * Maximum plaintext 32-bit signed integer value that can be encrypted.
 */
const _PLAINTEXT_SIGNED_INTEGER_MAX = BigInt(2147483647);

/**
 * Modulus to use for additive secret sharing of 32-bit signed integers.
 */
const _SECRET_SHARED_SIGNED_INTEGER_MODULUS = BigInt(4294967296);

/**
 * Maximum length of plaintext string values that can be encrypted.
 */
const _PLAINTEXT_STRING_BUFFER_LEN_MAX = 4096;

/**
 * Cluster configuration information.
 */
interface Cluster {
  nodes: object[]
};

/**
 * Record indicating what operations on ciphertexts are supported.
 */
interface Operations {
  store?: boolean,
  match?: boolean,
  sum?: boolean
};

/**
 * Data structure for representing all categories of secret key.
 */
interface SecretKey {
  value: {
    publicKey?: object,
    salt?: Uint8Array,
    symmetricKey?: Uint8Array
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
 * Concatenate two Uint8Array instances.
 */
function _concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const c = new Uint8Array(a.length + b.length);
  c.set(a);
  c.set(b, a.length);
  return c;
}

/**
 * Mathematically standard modulus operator.
 */
const _mod = function (n: bigint, m: bigint): bigint {
  n = (n < 0) ? n + m : n;
  return ((n % m) + m) % m;
};

/**
 * Componentwise XOR of two buffers.
 */
const _xor = function (a: Buffer, b: Buffer): Buffer {
  const length = Math.min(a.length, b.length);
  const r = Buffer.alloc(length);
  for (let i = 0; i < length; i++) {
    r[i] = a[i] ^ b[i];
  }
  return r;
};

/**
 * Return a SHA-512 hash of the supplied string.
 */
async function _sha512(bytes: Uint8Array): Promise<Uint8Array> {
  const buffer = await crypto.subtle.digest("SHA-512", bytes);
  return new Uint8Array(buffer);
}

/**
 * Encode a bytes-like object as a Base64 string (for compatibility with JSON).
 */
function _pack(b: Uint8Array): string {
  return Buffer.from(b).toString('base64');
}

/**
 * Decode a bytes-like object from its Base64 string encoding.
 */
function _unpack(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, 'base64'));
}

/**
 * Encode a numeric value or string as a byte array. The encoding includes
 * information about the type of the value (to enable decoding without any
 * additional context).
 */
function _encode(value: bigint | string): Uint8Array {
  let bytes: Uint8Array;

  // Encode signed big integer.
  if (typeof value === "bigint") {
    const buffer = Buffer.alloc(9);
    buffer[0] = 0; // First byte indicates encoded value is a 32-bit signed integer.
    buffer.writeBigInt64LE(value, 1);
    bytes = new Uint8Array(buffer);
  } else if (typeof value === "string") {
    bytes = new TextEncoder().encode(value);
    const byte = new Uint8Array(1);
    byte[0] = 1; // First byte indicates encoded value is a UTF-8 string.
    bytes = _concat(byte, bytes); 
  }

  return bytes;
}

/**
 * Decode a byte array back into a numeric value or string.
 */
function _decode(bytes: Uint8Array): bigint | string {
  if (bytes[0] === 0) { // Indicates encoded value is a 32-bit signed integer.
    return Buffer.from(bytes).readBigInt64LE(1);
  } else if (bytes[0] === 1) { // Indicates encoded value is a UTF-8 string.
    const decoder = new TextDecoder('utf-8');
    return decoder.decode(Buffer.from(bytes.subarray(1)));
  }
}

/**
 * Return a new secret key built according to what is specified in the supplied
 * cluster configuration and operation list.
 */
async function secretKey(
  cluster: Cluster,
  operations: Operations
): Promise<SecretKey>
{
  if (cluster === undefined || cluster === null) {
    throw new TypeError("valid cluster configuration is required");
  };

  if (cluster.nodes === undefined || cluster.nodes.length < 1) {
    throw new TypeError("cluster configuration must contain at least one node");
  };

  if (operations === undefined || operations === null) {
    throw new TypeError("valid operations specification is required");
  }

  if ( Object.keys(operations).length !== 1
    || (!operations.store && !operations.match && !operations.sum)
  ) {
    throw new TypeError("secret key must enable exactly one operation");
  }

  // Key object to be returned from this invocation.
  const instance = {
    value: null,
    cluster: cluster,
    operations: operations
  };

  if (instance.operations.store) {
    if (instance.cluster.nodes.length == 1) {
      await sodium.ready;
      instance.value = {symmetricKey: sodium.randombytes_buf(sodium.crypto_secretbox_KEYBYTES)};
    }
  }

  if (instance.operations.match) {
    const salt = new Uint8Array(64);
    crypto.getRandomValues(salt);
    instance.value = {salt: salt};
  }

  if (instance.operations.sum) {
    if (instance.cluster.nodes.length == 1) {
      const {publicKey, privateKey} = await paillierBigint.generateRandomKeys(2048);
      instance.value = privateKey;
    }
    // In a multi-node cluster, secret sharing is used (which does not require a
    // secret key value).
  }

  return instance;
}

/**
 * Return a new public key correponding to the supplied secret key (generated
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

  if (secretKey?.value?.publicKey != null) {
    instance.value = secretKey.value.publicKey;
  } else {
    throw new TypeError("cannot create public key for supplied secret key");
  }

  return instance;
}

/**
 * Return the ciphertext obtained by encrypting the supplied plaintext
 * using the supplied key.
 */
async function encrypt(
  key: PublicKey | SecretKey,
  plaintext: number | bigint | string
): Promise<bigint | string | bigint[] | string[]>
{
  // The values below may be used (depending on the plaintext type and the specific
  // kind of encryption being invoked).
  let bytes: Buffer;
  let bigInt: bigint;

  // Ensure the supplied plaintext is of one of the supported types, check that the
  // value satisfies the constraints, and (if applicable) perform standard conversion
  // and encoding of the plaintext.
  if (typeof plaintext === "number" || typeof plaintext === "bigint") {
    bigInt = (typeof plaintext === "number") ? BigInt(Number(plaintext)) : plaintext;

    if ((bigInt < _PLAINTEXT_SIGNED_INTEGER_MIN) || (bigInt > _PLAINTEXT_SIGNED_INTEGER_MAX)) {
      throw new TypeError("numeric plaintext must be a valid 32-bit signed integer");
    }
  } else if (typeof plaintext === "string") {
    bytes = Buffer.from(_encode(plaintext));

    if (bytes.length > _PLAINTEXT_STRING_BUFFER_LEN_MAX) {
      throw new TypeError("plaintext string must be possible to encode in 4096 bytes or fewer");
    }
  }

  // Ciphertext object to be returned from this invocation.
  let instance: bigint | string | bigint[] | string[];

  // Encrypt a value for storage and retrieval.
  if (key.operations.store) {
    const secretKey = key as SecretKey;

    // Encrypt a `number` or `bigint` instance for storage and retrieval.
    if (typeof plaintext === "number" || typeof plaintext === "bigint") {
      bytes = Buffer.from(_encode(bigInt));
    }

    // Encrypt a `string` instance for storage and retrieval requires no
    // further work (it is already encoded in `bytes`).

    // Encrypt the buffer using the secret key.
    if (key.cluster.nodes.length == 1) {
      // For single-node clusters, the data is encrypted using a symmetric key.
      const symmetricKey = secretKey.value.symmetricKey;
      await sodium.ready;
      const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
      instance = _pack(
        _concat(
          nonce,
          sodium.crypto_secretbox_easy(bytes, nonce, symmetricKey)
        )
      );
    } else if (key.cluster.nodes.length > 1) {
      // For multi-node clusters, the ciphertext is secret-shared across the nodes
      // using XOR.
      const shares: Uint8Array[] = [];
      let aggregate = Buffer.alloc(bytes.length, 0);
      for (let i = 0; i < key.cluster.nodes.length - 1; i++) {
        const mask = Buffer.from(sodium.randombytes_buf(bytes.length));
        aggregate = _xor(aggregate, mask);
        shares.push(new Uint8Array(mask));
      }
      shares.push(new Uint8Array(_xor(aggregate, Buffer.from(bytes))));
      instance = shares.map(_pack);
    }
  }

  // Encrypt (i.e., hash) a value for matching.
  if (key.operations.match) {
    const secretKey = key as SecretKey;

    // Encrypt (i.e., hash) a `number` or `bigint` instance for matching.
    if (typeof plaintext === "number" || typeof plaintext === "bigint") {
      bytes = Buffer.from(_encode(bigInt));
    }

    // Encrypting (i.e., hashing) a `string` instance for matching requires no
    // further work (it is already encoded in `bytes`).
 
    // The deterministic salted hash of the encoded value serves as the ciphertext.
    const hashed = await _sha512(_concat(secretKey.value.salt, bytes));
    const packed = _pack(hashed);

    // For multi-node clusters, the ciphertext is replicated across all nodes.
    if (key.cluster.nodes.length == 1) { 
      instance = packed;
    } else {
      instance = key.cluster.nodes.map((_) => packed);
    }
  }

  // Encrypt a `number` or `bigint` instance for summation.
  if (key.operations.sum) {

    // Only 32-bit signed integer values are supported.
    if (!(typeof plaintext === "number" || typeof plaintext === "bigint")) {
      throw new TypeError("plaintext to encrypt for sum operation must be number or bigint");
    }

    // Encrypt the integer value using either Paillier or additive secret sharing.
    if (key.cluster.nodes.length == 1) {
      // Use Paillier for single-node clusters.

      // Extract public key from secret key if a secret key was supplied and rebuild the
      // public key object for the Paillier library.
      let paillierPublicKey: paillierBigint.PublicKey;

      if ("publicKey" in key.value) { // Secret key was supplied.
        paillierPublicKey = key.value.publicKey as paillierBigint.PublicKey;
      } else { // Public key was supplied.
        paillierPublicKey = (key as PublicKey).value as paillierBigint.PublicKey;
      }
      // Construct again to gain access to methods.
      paillierPublicKey = new paillierBigint.PublicKey(
        BigInt(paillierPublicKey.n),
        BigInt(paillierPublicKey.g)
      );
      instance = paillierPublicKey.encrypt(bigInt - _PLAINTEXT_SIGNED_INTEGER_MIN);
    } else {
      // Use additive secret sharing for multi-node clusters.
      const shares: bigint[] = [];
      let total = BigInt(0);
      for (let i = 0; i < key.cluster.nodes.length - 1; i++) {
        const mask = Buffer.alloc(4);
        crypto.getRandomValues(mask);
        const share = BigInt(mask.readUInt32BE(0));
        shares.push(share);
        total = _mod(total + share, _SECRET_SHARED_SIGNED_INTEGER_MODULUS);
      }
      shares.push(_mod(bigInt - total, _SECRET_SHARED_SIGNED_INTEGER_MODULUS));
      instance = shares;
    }
  }

  return instance;
}

/**
 * Return the plaintext obtained by decrypting the supplied ciphertext
 * using the supplied secret key.
 */
async function decrypt(
  secretKey: SecretKey,
  ciphertext: (bigint | bigint[] | string | string[])
): Promise<bigint | string>
{
  // Ensure the supplied ciphertext has a type that is compatible with the supplied
  // secret key.
  if (secretKey.cluster.nodes.length == 1) {
    if (typeof ciphertext !== "bigint" &&  typeof ciphertext !== "string") {
      throw new TypeError("secret key requires a valid ciphertext from a single-node cluster");
    }
  } else {
    if ( !Array.isArray(ciphertext) 
      || (
            !(ciphertext.every(c => typeof c === "bigint")) &&
            !(ciphertext.every(c => typeof c === "string"))
         )
       ) {
      throw new TypeError("secret key requires a valid ciphertext from a multi-node cluster");
    }
  }

  // Result object to be returned from this invocation.
  let instance: (bigint | string);

  // Decrypt a value that was encrypted for storage.
  if (secretKey.operations.store) {
    // Decrypt based on whether the key is for a a single-node or multi-node cluster.
    if (secretKey.cluster.nodes.length == 1) {
      // Single-node clusters use symmetric encryption.
      await sodium.ready;
      const symmetricKey = secretKey.value.symmetricKey;
      const bytes = _unpack(ciphertext as string);
      const nonce = bytes.subarray(0, sodium.crypto_secretbox_NONCEBYTES);
      const cipher = bytes.subarray(sodium.crypto_secretbox_NONCEBYTES);
      const plain = sodium.crypto_secretbox_open_easy(cipher, nonce, symmetricKey);
      instance = _decode(plain);
    } else {
      // Multi-node clusters use XOR-based secret sharing.
      const shares = (ciphertext as string[]).map(_unpack);
      let bytes = Buffer.from(shares[0]);
      for (let i = 1; i < shares.length; i++) {
        bytes = _xor(bytes, Buffer.from(shares[i]));
      }
      instance = _decode(bytes);
    }

    return instance;
  }

  // Decrypt an encrypted numerical value that supports summation.
  if (secretKey.operations.sum) {
    // Decrypt based on whether the key is for a a single-node or multi-node cluster.
    if (secretKey.cluster.nodes.length == 1) {
      // Single-node clusters use Paillier ciphertexts.
      const paillierPrivateKey = secretKey.value as paillierBigint.PrivateKey;
      instance = paillierPrivateKey.decrypt(ciphertext as bigint);
      instance += _PLAINTEXT_SIGNED_INTEGER_MIN;
    } else {
      // Multi-node clusters use additive secret sharing.
      const shares = ciphertext as bigint[];
      instance = BigInt(0);
      for (const share of shares) {
        instance = _mod(instance + share, _SECRET_SHARED_SIGNED_INTEGER_MODULUS);
      }
      if (instance > _PLAINTEXT_SIGNED_INTEGER_MAX) {
        instance -= _SECRET_SHARED_SIGNED_INTEGER_MODULUS;
      }
    }

    return instance;
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
