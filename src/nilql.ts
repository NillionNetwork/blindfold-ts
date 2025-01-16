/**
 * NilQL: Library for working with encrypted data within NilDB queries and replies.
 */
import sodium from "libsodium-wrappers-sumo";
import * as paillierBigint from "paillier-bigint";

/**
 * Helper function to compare two arrays of object keys (i.e., strings).
 */
function equalKeys(a: Array<string>, b: Array<string>) {
  const zip = (a: Array<string>, b: Array<string>) =>
    a.map((k, i) => [k, b[i]]);
  return zip(a, b).every((pair) => pair[0] === pair[1]);
}

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
  nodes: object[];
}

/**
 * Record indicating what operations on ciphertexts are supported.
 */
interface Operations {
  store?: boolean;
  match?: boolean;
  sum?: boolean;
}

/**
 * Data structure for representing all categories of secret key.
 */
class SecretKey {
  material: object;
  cluster: Cluster;
  operations: Operations;

  private constructor(cluster: Cluster | null, operations: Operations | null) {
    if (cluster === undefined || cluster === null) {
      throw new TypeError("valid cluster configuration is required");
    }

    if (cluster.nodes === undefined || cluster.nodes.length < 1) {
      throw new TypeError(
        "cluster configuration must contain at least one node",
      );
    }

    if (operations === undefined || operations === null) {
      throw new TypeError("valid operations specification is required");
    }

    if (
      Object.keys(operations).length !== 1 ||
      (!operations.store && !operations.match && !operations.sum)
    ) {
      throw new TypeError("secret key must enable exactly one operation");
    }

    this.material = {};
    this.cluster = cluster;
    this.operations = operations;

    if (this.operations.store) {
      if (this.cluster.nodes.length === 1) {
        this.material = sodium.randombytes_buf(
          sodium.crypto_secretbox_KEYBYTES,
        );
      }
    }

    if (this.operations.match) {
      this.material = sodium.randombytes_buf(64); // Salt for hashing.
    }

    // For the sum operation, initialization must occur within `generate`.
  }

  /**
   * Generate a new secret key built according to what is specified in the supplied
   * cluster configuration and operation list.
   */
  public static async generate(
    cluster: Cluster | null,
    operations: Operations | null,
  ): Promise<SecretKey> {
    const secretKey = new SecretKey(cluster, operations);
    if (secretKey instanceof SecretKey && secretKey.operations.sum) {
      if (secretKey.cluster.nodes.length === 1) {
        const { privateKey } = await paillierBigint.generateRandomKeys(2048);
        secretKey.material = privateKey;
      }
      // In a multi-node cluster, secret sharing is used (which does not require a
      // secret key value).
    }
    return secretKey;
  }

  /**
   * Return a JSON-compatible object representation of the key instance.
   */
  public dump(): object {
    const object = {
      material: {},
      cluster: this.cluster,
      operations: this.operations,
    };

    if (Object.keys(this.material).length === 0) {
      // There is no key material for clusters with multiple nodes.
    } else if (this.material instanceof Uint8Array) {
      object.material = _pack(this.material);
    } else {
      // Secret key for Paillier encryption.
      const privateKey = this.material as {
        publicKey: { n: bigint; g: bigint };
        lambda: bigint;
        mu: bigint;
      };
      object.material = {
        n: privateKey.publicKey.n.toString(),
        g: privateKey.publicKey.g.toString(),
        l: privateKey.lambda.toString(),
        m: privateKey.mu.toString(),
      };
    }

    return object;
  }

  /**
   * Create an instance from its JSON-compatible object representation.
   */
  public static load(object: object): SecretKey {
    const errorInvalid = new TypeError(
      "invalid object representation of a secret key",
    );

    if (
      !("material" in object && "cluster" in object && "operations" in object)
    ) {
      throw errorInvalid;
    }

    const secretKey = new SecretKey(
      object.cluster as Cluster,
      object.operations as Operations,
    );

    const material = object.material as object;

    if (Object.keys(material).length === 0) {
      // There is no key material for clusters with multiple nodes.
    } else if (typeof material === "string") {
      secretKey.material = _unpack(material);
    } else {
      // Secret key for Paillier encryption.
      if (
        !(
          "l" in material &&
          "m" in material &&
          "n" in material &&
          "g" in material
        )
      ) {
        throw errorInvalid;
      }

      if (
        !(
          typeof material.l === "string" &&
          typeof material.m === "string" &&
          typeof material.n === "string" &&
          typeof material.g === "string"
        )
      ) {
        throw errorInvalid;
      }

      secretKey.material = new paillierBigint.PrivateKey(
        BigInt(material.l as string),
        BigInt(material.m as string),
        new paillierBigint.PublicKey(
          BigInt(material.n as string),
          BigInt(material.g as string),
        ),
      );
    }

    return secretKey;
  }
}

/**
 * Data structure for representing all categories of public key.
 */
class PublicKey {
  material: object;
  cluster: Cluster;
  operations: Operations;

  private constructor(secretKey: SecretKey) {
    this.cluster = secretKey.cluster;
    this.operations = secretKey.operations;

    if (
      "publicKey" in secretKey.material &&
      secretKey.material.publicKey instanceof paillierBigint.PublicKey
    ) {
      this.material = secretKey.material.publicKey;
    } else {
      throw new TypeError("cannot create public key for supplied secret key");
    }
  }

  /**
   * Generate a new public key corresponding to the supplied secret key
   * according to any information contained therein.
   */
  public static async generate(secretKey: SecretKey): Promise<PublicKey> {
    return new PublicKey(secretKey);
  }

  /**
   * Return a JSON-compatible object representation of the key instance.
   */
  public dump(): object {
    const object = {
      material: {},
      cluster: this.cluster,
      operations: this.operations,
    };

    if ("n" in this.material && "g" in this.material) {
      // Public key for Paillier encryption.
      const publicKey = this.material as paillierBigint.PublicKey;
      object.material = {
        n: publicKey.n.toString(),
        g: publicKey.g.toString(),
      };
    }

    return object;
  }

  /**
   * Create an instance from its JSON-compatible object representation.
   */
  public static load(object: object): PublicKey {
    const errorInvalid = new TypeError(
      "invalid object representation of a public key",
    );

    if (
      !("material" in object && "cluster" in object && "operations" in object)
    ) {
      throw errorInvalid;
    }

    const publicKey = {} as PublicKey;
    publicKey.cluster = object.cluster as Cluster;
    publicKey.operations = object.operations as Operations;

    const material = object.material as object;

    if (!("n" in material && "g" in material)) {
      throw errorInvalid;
    }

    if (!(typeof material.n === "string" && typeof material.g === "string")) {
      throw errorInvalid;
    }

    publicKey.material = new paillierBigint.PublicKey(
      BigInt(material.n as string),
      BigInt(material.g as string),
    );

    return publicKey;
  }
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
 * Mathematically standard modulus operator.
 */
const _mod = (n: bigint, m: bigint): bigint => {
  const num = n < 0 ? n + m : n;
  return ((num % m) + m) % m;
};

/**
 * Componentwise XOR of two buffers.
 */
const _xor = (a: Buffer, b: Buffer): Buffer => {
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
  return Buffer.from(b).toString("base64");
}

/**
 * Decode a bytes-like object from its Base64 string encoding.
 */
function _unpack(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, "base64"));
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
  } else {
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
  if (bytes[0] === 0) {
    // Indicates encoded value is a 32-bit signed integer.
    return Buffer.from(bytes).readBigInt64LE(1);
  }
  // Indicates encoded value is a UTF-8 string.
  const decoder = new TextDecoder("utf-8");
  return decoder.decode(Buffer.from(bytes.subarray(1)));
}

/**
 * Return a new secret key built according to what is specified in the supplied
 * cluster configuration and operation list.
 */
async function secretKey(
  cluster: Cluster | null,
  operations: Operations | null,
): Promise<SecretKey> {
  // Key object to be returned from this invocation.
  return SecretKey.generate(cluster, operations);
}

/**
 * Return the ciphertext obtained by encrypting the supplied plaintext
 * using the supplied key.
 */
async function encrypt(
  key: PublicKey | SecretKey,
  plaintext: number | bigint | string,
): Promise<bigint | string | number[] | string[]> {
  await sodium.ready;

  // The values below may be used (depending on the plaintext type and the specific
  // kind of encryption being invoked).
  let bytes: Buffer = Buffer.from(new Uint8Array());
  let bigInt = 0n;

  // Ensure the supplied plaintext is of one of the supported types, check that the
  // value satisfies the constraints, and (if applicable) perform standard conversion
  // and encoding of the plaintext.
  if (typeof plaintext === "number" || typeof plaintext === "bigint") {
    bigInt =
      typeof plaintext === "number" ? BigInt(Number(plaintext)) : plaintext;

    if (
      bigInt < _PLAINTEXT_SIGNED_INTEGER_MIN ||
      bigInt > _PLAINTEXT_SIGNED_INTEGER_MAX
    ) {
      throw new TypeError(
        "numeric plaintext must be a valid 32-bit signed integer",
      );
    }
  } else {
    bytes = Buffer.from(_encode(plaintext));

    if (bytes.length > _PLAINTEXT_STRING_BUFFER_LEN_MAX) {
      throw new TypeError(
        "string plaintext must be possible to encode in 4096 bytes or fewer",
      );
    }
  }

  // Ciphertext object to be returned from this invocation.
  let instance: bigint | string | number[] | string[];

  // Encrypt a value for storage and retrieval.
  if (key.operations.store) {
    const secretKey = key as SecretKey;

    // Encrypt a `number` or `bigint` instance for storage and retrieval.
    if (typeof plaintext === "number" || typeof plaintext === "bigint") {
      bytes = Buffer.from(_encode(bigInt));
    }

    // Encrypting a `string` instance for storage and retrieval requires no
    // further work (it is already encoded in `bytes`).

    // Encrypt the buffer using the secret key.
    if (key.cluster.nodes.length === 1) {
      // For single-node clusters, the data is encrypted using a symmetric key.
      const symmetricKey = secretKey.material as Uint8Array;
      const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
      instance = _pack(
        _concat(
          nonce,
          sodium.crypto_secretbox_easy(bytes, nonce, symmetricKey),
        ),
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
    const hashed = await _sha512(
      _concat(secretKey.material as Uint8Array, bytes),
    );
    const packed = _pack(hashed);

    // For multi-node clusters, the ciphertext is replicated across all nodes.
    if (key.cluster.nodes.length === 1) {
      instance = packed;
    } else {
      instance = key.cluster.nodes.map((_) => packed);
    }
  }

  // Encrypt a `number` or `bigint` instance for summation.
  if (key.operations.sum) {
    // Only 32-bit signed integer values are supported.
    if (!(typeof plaintext === "number" || typeof plaintext === "bigint")) {
      throw new TypeError(
        "plaintext to encrypt for sum operation must be number or bigint",
      );
    }

    // Encrypt the integer value using either Paillier or additive secret sharing.
    if (key.cluster.nodes.length === 1) {
      // Use Paillier for single-node clusters.

      // Extract public key from secret key if a secret key was supplied and rebuild the
      // public key object for the Paillier library.
      let paillierPublicKey: paillierBigint.PublicKey;

      if ("publicKey" in key.material) {
        // Secret key was supplied.
        paillierPublicKey = key.material.publicKey as paillierBigint.PublicKey;
      } else {
        // Public key was supplied.
        paillierPublicKey = (key as PublicKey)
          .material as paillierBigint.PublicKey;
      }

      // Construct again to gain access to methods.
      paillierPublicKey = new paillierBigint.PublicKey(
        paillierPublicKey.n,
        paillierPublicKey.g,
      );
      instance = paillierPublicKey.encrypt(
        bigInt - _PLAINTEXT_SIGNED_INTEGER_MIN,
      );
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
      instance = shares.map(Number);
    }
  }

  // @ts-expect-error: fixing requires an out-of-scope type refactor
  return instance;
}

/**
 * Return the plaintext obtained by decrypting the supplied ciphertext
 * using the supplied secret key.
 */
async function decrypt(
  secretKey: SecretKey,
  ciphertext: bigint | number[] | string | string[],
): Promise<bigint | string> {
  await sodium.ready;

  // Ensure the supplied ciphertext has a type that is compatible with the supplied
  // secret key.
  if (secretKey.cluster.nodes.length === 1) {
    if (typeof ciphertext !== "bigint" && typeof ciphertext !== "string") {
      throw new TypeError(
        "secret key requires a valid ciphertext from a single-node cluster",
      );
    }
  } else {
    if (
      !Array.isArray(ciphertext) ||
      (!ciphertext.every((c) => typeof c === "number") &&
        !ciphertext.every((c) => typeof c === "string"))
    ) {
      throw new TypeError(
        "secret key requires a valid ciphertext from a multi-node cluster",
      );
    }

    if (secretKey.cluster.nodes.length !== ciphertext.length) {
      throw new TypeError(
        "secret key and ciphertext must have the same associated cluster size",
      );
    }
  }

  // Result object to be returned from this invocation.
  let instance: bigint | string;

  // Decrypt a value that was encrypted for storage.
  if (secretKey.operations.store) {
    // Decrypt based on whether the key is for a single-node or multi-node cluster.
    if (secretKey.cluster.nodes.length === 1) {
      // Single-node clusters use symmetric encryption.
      const symmetricKey = secretKey.material as Uint8Array;
      const bytes = _unpack(ciphertext as string);
      const nonce = bytes.subarray(0, sodium.crypto_secretbox_NONCEBYTES);
      const cipher = bytes.subarray(sodium.crypto_secretbox_NONCEBYTES);

      try {
        const plain = sodium.crypto_secretbox_open_easy(
          cipher,
          nonce,
          symmetricKey,
        );
        instance = _decode(plain);
      } catch (error) {
        throw new TypeError(
          "ciphertext cannot be decrypted using supplied secret key",
        );
      }
    } else {
      // Multi-node clusters use XOR-based secret sharing.
      const shares = (ciphertext as string[]).map(_unpack);
      let bytes = Buffer.from(shares[0]);
      for (let i = 1; i < shares.length; i++) {
        bytes = Buffer.from(_xor(bytes, Buffer.from(shares[i])));
      }
      instance = _decode(bytes);
    }

    return instance;
  }

  // Decrypt an encrypted numerical value that supports summation.
  if (secretKey.operations.sum) {
    // Decrypt based on whether the key is for a single-node or multi-node cluster.
    if (secretKey.cluster.nodes.length === 1) {
      // Single-node clusters use Paillier ciphertexts.
      const paillierPrivateKey =
        secretKey.material as paillierBigint.PrivateKey;
      instance = paillierPrivateKey.decrypt(ciphertext as bigint);
      instance += _PLAINTEXT_SIGNED_INTEGER_MIN;
    } else {
      // Multi-node clusters use additive secret sharing.
      const shares = ciphertext as number[];
      instance = BigInt(0);
      for (const share of shares) {
        instance = _mod(
          instance + BigInt(share),
          _SECRET_SHARED_SIGNED_INTEGER_MODULUS,
        );
      }
      if (instance > _PLAINTEXT_SIGNED_INTEGER_MAX) {
        instance -= _SECRET_SHARED_SIGNED_INTEGER_MODULUS;
      }
    }

    return instance;
  }

  throw new TypeError(
    "ciphertext cannot be decrypted using supplied secret key",
  );
}

/**
 * Convert an object that may contain ciphertexts intended for multi-node
 * clusters into secret shares of that object. Shallow copies are created
 * whenever possible.
 */
function allot(object: object): object[] {
  if (
    typeof object === "string" ||
    typeof object === "number" ||
    typeof object === "boolean"
  ) {
    return [object];
  }

  if (Array.isArray(object)) {
    const results = (object as Array<object>).map(allot);

    // Determine the number of shares that must be created.
    let multiplicity = 1;
    for (let i = 0; i < results.length; i++) {
      const result = results[i];
      if (result.length !== 1) {
        if (multiplicity === 1) {
          multiplicity = result.length;
        } else if (multiplicity !== result.length) {
          throw new TypeError("number of shares is not consistent");
        }
      }
    }

    // Create the appropriate number of shares.
    const shares = [];
    for (let i = 0; i < multiplicity; i++) {
      const share = [];
      for (let j = 0; j < results.length; j++) {
        share.push(results[j][results[j].length === 1 ? 0 : i]);
      }
      shares.push(share);
    }

    return shares;
  }

  if (object instanceof Object) {
    // Base case: an array of shares that must be allotted to nodes.
    if ("$allot" in object) {
      const items = object.$allot as Array<object>;
      const shares = [];
      for (let i = 0; i < items.length; i++) {
        shares.push({ $share: items[i] });
      }
      return shares;
    }

    // Object is a general-purpose key-value mapping.
    const existing = object as { [k: string]: object };
    const results: { [k: string]: object } = {};
    let multiplicity = 1;
    for (const key in existing) {
      const result = allot(existing[key]);
      results[key] = result;
      if (result.length !== 1) {
        if (multiplicity === 1) {
          multiplicity = result.length;
        } else if (multiplicity !== result.length) {
          throw new TypeError("number of shares is not consistent");
        }
      }
    }

    // Create the appropriate number of shares.
    const shares = [];
    for (let i = 0; i < multiplicity; i++) {
      const share: { [k: string]: object } = {};
      for (const key in results) {
        const resultsForKey = results[key] as Array<object>;
        share[key] = resultsForKey[resultsForKey.length === 1 ? 0 : i];
      }
      shares.push(share);
    }

    return shares;
  }

  throw new TypeError("number, string, array, or object expected");
}

/**
 * Convert an array of compatible secret share objects into a single object
 * that deduplicates matching plaintext leaf values and recombines matching
 * secret share leaf values.
 */
async function unify(
  secretKey: SecretKey,
  objects: object[],
): Promise<object | Array<object>> {
  if (objects.length === 1) {
    return objects[0];
  }

  if (objects.every((object) => Array.isArray(object))) {
    const length = objects[0].length;
    if (objects.every((object) => object.length === length)) {
      const results = [];
      for (let i = 0; i < length; i++) {
        const result = await unify(
          secretKey,
          objects.map((object) => object[i]),
        );
        results.push(result);
      }
      return results;
    }
  }

  if (objects.every((object) => object instanceof Object)) {
    // Objects are shares.
    if (objects.every((object) => "$share" in object)) {
      const shares = objects.map((object) => object.$share);
      const decrypted = decrypt(secretKey, shares as string[] | number[]);
      return decrypted as object;
    }

    // Objects are general-purpose key-value mappings.
    const keys: Array<string> = Object.keys(objects[0]);
    const zip = (a: Array<string>, b: Array<string>) =>
      a.map((k, i) => [k, b[i]]);
    if (objects.every((object) => equalKeys(keys, Object.keys(object)))) {
      const results: { [k: string]: object } = {};
      for (const key in objects[0]) {
        const result = await unify(
          secretKey,
          objects.map((object) => (object as { [k: string]: object })[key]),
        );
        results[key] = result;
      }
      return results;
    }
  }

  // Base case: all objects must be equivalent.
  let allValuesEqual = true;
  for (let i = 1; i < objects.length; i++) {
    allValuesEqual &&= objects[0] === objects[i];
  }
  if (allValuesEqual) {
    return objects[0];
  }

  throw new TypeError("array of compatible share objects expected");
}

/**
 * Export library wrapper.
 */
export const nilql = {
  SecretKey,
  PublicKey,
  encrypt,
  decrypt,
  allot,
  unify,
} as const;
