/**
 * TypeScript library for working with encrypted data within nilDB queries
 * and replies.
 */
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha512 } from "@noble/hashes/sha2.js";
import * as bcu from "bigint-crypto-utils";
import sodium from "libsodium-wrappers-sumo";
import * as paillierBigint from "paillier-bigint";

/**
 * Length in bits of Paillier keys.
 */
const _PAILLIER_KEY_LENGTH: number = 2048;

/**
 * Modulus to use for secret shares of 32-bit signed integers.
 */
const _SECRET_SHARED_SIGNED_INTEGER_MODULUS: bigint = 2n ** 32n + 15n;

/**
 * Minimum plaintext 32-bit signed integer value that can be encrypted.
 */
const _PLAINTEXT_SIGNED_INTEGER_MIN: bigint = -(2n ** 31n);

/**
 * Maximum plaintext 32-bit signed integer value that can be encrypted.
 */
const _PLAINTEXT_SIGNED_INTEGER_MAX: bigint = 2n ** 31n - 1n;

/**
 * Maximum length of plaintext string values that can be encrypted.
 */
const _PLAINTEXT_STRING_BUFFER_LEN_MAX: number = 4096;

/**
 * Attempt to obtain Web Crypto API object with proper validation.
 */
function _getCrypto(): Crypto {
  if (!globalThis.crypto) {
    throw new Error("Web Crypto API is not available");
  }
  return globalThis.crypto;
}

/**
 * Mathematically standard modulus operator.
 */
function _mod(n: bigint, m: bigint): bigint {
  return (((n < 0 ? n + m : n) % m) + m) % m;
}

/**
 * Convert a `Uint8Array` to the unsigned `bigint` they represent (assuming
 * a little-endian representation).
 */
function _bigIntFromUint8Array(array: Uint8Array): bigint {
  return Array.from(array)
    .reverse()
    .reduce((acc, byte) => (acc << 8n) + BigInt(byte), 0n);
}

/**
 * Convert an unsigned `bigint` to a `Uint8Array` that represents it (assuming
 * a little-endian representation).
 */
function _bigIntToUint8Array(num: bigint, length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  for (let i = 0; i < length; i++) {
    // 1. Shift the required byte (i * 8 bits) to the least significant position
    // 2. Apply a bitmask (0xFF) to get only the lowest 8 bits (the current byte)
    // 3. Convert the result back to a standard number for storage in Uint8Array
    bytes[i] = Number((num >> BigInt(i * 8)) & 0xffn);
  }
  return bytes;
}

/**
 * Componentwise XOR of two buffers.
 */
function _xor(a: Buffer, b: Buffer): Buffer {
  const length = Math.min(a.length, b.length);
  const r = Buffer.alloc(length);
  for (let i = 0; i < length; i++) {
    r[i] = a[i] ^ b[i];
  }
  return r;
}

/**
 * Concatenate two `Uint8Array` instances.
 */
function _concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const c = new Uint8Array(a.length + b.length);
  c.set(a);
  c.set(b, a.length);
  return c;
}

/**
 * Determine whether the supplied argument is a simple object.
 */
function _isSimpleObject(object: object | undefined): boolean {
  return (
    object !== undefined &&
    object !== null &&
    typeof object === "object" &&
    !Array.isArray(object) &&
    Object.prototype.toString.call(object) === "[object Object]"
  );
}

/**
 * Helper function to compare two arrays of strings.
 */
function _equalKeys(a: string[], b: string[]) {
  const zip = (a: string[], b: string[]) => a.map((k, i) => [k, b[i]]);
  return zip(a, b).every((pair) => pair[0] === pair[1]);
}

/**
 * Return a SHA-512 hash of the supplied string.
 */
async function _sha512(bytes: Uint8Array): Promise<Uint8Array> {
  const buffer = await _getCrypto().subtle.digest("SHA-512", bytes);
  return new Uint8Array(buffer);
}

/**
 * Return a random byte array of the specified length (using the seed if one
 * is supplied).
 */
async function _randomBytes(
  length: number,
  seed: Uint8Array | undefined = undefined,
  salt: Uint8Array | undefined = undefined,
): Promise<Uint8Array> {
  await sodium.ready;

  if (seed !== undefined) {
    try {
      return hkdf(
        sha512,
        seed,
        salt || new Uint8Array([0x00]),
        new Uint8Array(0),
        length,
      );
      /* v8 ignore next 3 */ // This scenario is outside the scope of tests.
    } catch (error) {
      throw new Error(`failed to derive key from seed: ${error}`);
    }
  }

  return sodium.randombytes_buf(length);
}

/**
 * Return a random integer value within the specified range (using the seed if
 * one is supplied) by leveraging rejection sampling.
 */
async function _randomInteger(
  minimum: bigint,
  maximum: bigint,
  seed: Uint8Array | undefined = undefined,
): Promise<bigint> {
  /* v8 ignore next 3 */ // Invocation arguments are always constants.
  if (minimum < 0 || minimum > 1) {
    throw new RangeError("minimum must be 0 or 1");
  }

  /* v8 ignore next 5 */ // Invocation arguments are always constants.
  if (maximum <= minimum || maximum >= _SECRET_SHARED_SIGNED_INTEGER_MODULUS) {
    throw new RangeError(
      "maximum must be greater than the minimum and less than the modulus",
    );
  }

  const range = maximum - minimum;
  let integer: bigint | null = null;
  let index = 0n;
  while (integer === null || integer > range) {
    const index_bytes = Buffer.alloc(8);
    index_bytes.writeBigInt64LE(index, 0);
    const uint8Array = await _randomBytes(8, seed, index_bytes);
    index++;

    uint8Array[4] &= 0b00000001;
    uint8Array[5] &= 0b00000000;
    uint8Array[6] &= 0b00000000;
    uint8Array[7] &= 0b00000000;
    const buffer = Buffer.from(uint8Array);
    const small = BigInt(buffer.readUInt32LE(0));
    const large = BigInt(buffer.readUInt32LE(4));
    integer = small + large * 2n ** 32n;
  }

  return minimum + integer;
}

/**
 * Evaluates polynomial (represented as an array of coefficients) at `x`.
 */
function _shamirsEval(
  coefficients: bigint[],
  x: bigint,
  prime: bigint,
): bigint {
  let accum = BigInt(0);
  for (let i = coefficients.length - 1; i >= 0; i--) {
    accum = (_mod(accum * x, prime) + coefficients[i]) % prime;
  }
  return accum;
}

/**
 * Uses Shamir's secret sharing scheme to generate and return a collection of
 * secret shares representing the supplied plaintext.
 */
async function _shamirsShares(
  plaintext: bigint,
  quantity: number,
  prime: bigint,
  threshold: number | undefined,
): Promise<[bigint, bigint][]> {
  /* v8 ignore next */ // All invocations supply an explicit threshold.
  const threshold_ = threshold === undefined ? quantity : threshold;
  if (threshold_ > quantity) {
    throw new Error(
      "quantity of shares cannot be less than the reconstruction threshold",
    );
  }

  // Generate polynomial coefficients, ensuring they are within the correct range.
  const coefficients: bigint[] = [plaintext];
  for (let i = 1; i < threshold_; i++) {
    coefficients.push(await _randomInteger(1n, prime - 1n));
  }

  // Generate the shares.
  const points: [bigint, bigint][] = [];
  for (let i = 1; i <= quantity; i++) {
    const x = BigInt(i);
    const y = _shamirsEval(coefficients, x, prime);
    points.push([x, y]);
  }
  return points;
}

/**
 * Recover the plaintext value from the supplied array of Shamir's secret shares.
 */
function _shamirsRecover(shares: bigint[][], prime: bigint): bigint {
  let secret = 0n;

  for (let i = 0; i < shares.length; i++) {
    let num = 1n;
    let denom = 1n;

    for (let j = 0; j < shares.length; j++) {
      if (i !== j) {
        num = _mod(num * -shares[j][0], prime);
        denom = _mod(denom * (shares[i][0] - shares[j][0]), prime);
      }
    }

    const invDenom = bcu.modInv(denom, prime); // Modular inverse
    secret = _mod(secret + shares[i][1] * num * invDenom, prime);
  }

  return secret;
}

/**
 * Encode a byte array object as a Base64 string (for compatibility with JSON).
 */
function _pack(b: Uint8Array): string {
  return Buffer.from(b).toString("base64");
}

/**
 * Decode a bytes array from its Base64 string encoding.
 */
function _unpack(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, "base64"));
}

/**
 * Encode an integer, string, or binary plaintext as a byte array. The encoding
 * includes information about the type of the value in the first byte (to enable
 * decoding without any additional context).
 */
function _encode(value: bigint | string | Uint8Array): Uint8Array {
  let bytes: Uint8Array;

  // Encode signed big integer.
  if (typeof value === "bigint") {
    const buffer = Buffer.alloc(9);
    buffer[0] = 0; // First byte indicates encoded value is a 32-bit signed integer.
    buffer.writeBigInt64LE(value, 1);
    bytes = new Uint8Array(buffer);
  } else if ((value as object) instanceof Uint8Array) {
    const byte = new Uint8Array([2]); // Encoded value is binary data.
    bytes = _concat(byte, value as Uint8Array);
  } else {
    bytes = new TextEncoder().encode(value as string);
    const byte = new Uint8Array([1]); // Encoded value is a UTF-8 string.
    bytes = _concat(byte, bytes);
  }

  return bytes;
}

/**
 * Decode a byte array back into an integer, string, or binary plaintext.
 */
function _decode(bytes: Uint8Array): bigint | string | Uint8Array {
  if (bytes[0] === 0) {
    // Indicates encoded value is a 32-bit signed integer.
    return Buffer.from(bytes).readBigInt64LE(1);
  }

  if (bytes[0] === 2) {
    // Indicates encoded value is binary data.
    return new Uint8Array(bytes.subarray(1));
  }

  // Encoded value must be a UTF-8 string.
  const decoder = new TextDecoder("utf-8");
  return decoder.decode(Buffer.from(bytes.subarray(1)));
}

/**
 * Cluster configuration information.
 */
export class Cluster {
  nodes: object[];

  constructor(configuration: { nodes: object[] }) {
    if (!_isSimpleObject(configuration)) {
      throw new TypeError("cluster configuration must be a simple object");
    }

    if (!("nodes" in configuration)) {
      throw new Error("cluster configuration must specify nodes");
    }

    if (!Array.isArray(configuration.nodes)) {
      throw new Error(
        "cluster configuration nodes specification must be an array",
      );
    }

    if (configuration.nodes.length < 1) {
      throw new Error("cluster configuration must contain at least one node");
    }

    this.nodes = configuration.nodes;
  }
}

/**
 * Specification identifying what operations on ciphertexts a key supports.
 */
export class Operations {
  store?: boolean;
  match?: boolean;
  sum?: boolean;

  constructor(specification: {
    store?: boolean;
    match?: boolean;
    sum?: boolean;
  }) {
    if (!_isSimpleObject(specification)) {
      throw new TypeError("operations specification must be a simple object");
    }

    if (
      !Object.keys(specification).every((o) =>
        ["store", "match", "sum"].includes(o),
      )
    ) {
      throw new Error(
        "permitted operations are limited to store, match, and sum",
      );
    }

    if (
      !Object.keys(specification).every(
        (o) =>
          typeof specification[o as keyof typeof specification] === "boolean",
      )
    ) {
      throw new TypeError("operations specification values must be boolean");
    }

    if (Object.values(specification).filter((o) => o).length !== 1) {
      throw new Error(
        "operations specification must enable exactly one operation",
      );
    }

    // Ensure this object only contains the operation being specified as a key
    // (and no entries mapping to the `undefined` value).
    delete this.store;
    delete this.match;
    delete this.sum;

    if ("store" in specification) {
      this.store = specification.store;
    }

    if ("match" in specification) {
      this.match = specification.match;
    }

    if ("sum" in specification) {
      this.sum = specification.sum;
    }
  }
}

/**
 * Ensure the provided cluster configuration, operations specification, and
 * threshold are valid and compatible with one another.
 */
function _validateKeyAttributes(
  cluster: Cluster,
  operations: Operations,
  threshold: number | undefined = undefined,
) {
  if (threshold !== undefined) {
    if (typeof threshold !== "number") {
      throw new TypeError("threshold must be a number");
    }

    if (!Number.isInteger(threshold)) {
      throw new Error("threshold must be an integer number");
    }

    if (cluster.nodes.length === 1) {
      throw new Error(
        "thresholds are only supported for multiple-node clusters",
      );
    }

    if (threshold < 1 || threshold > cluster.nodes.length) {
      throw new Error(
        "threshold must be a positive integer not larger than the cluster size",
      );
    }

    if (!operations.sum && !operations.store) {
      throw new Error(
        "thresholds are only supported for the store and sum operations",
      );
    }
  }
}

/**
 * Data structure for representing all categories of secret key instances.
 */
export class SecretKey {
  cluster: Cluster;
  operations: Operations;
  threshold?: number;
  material: Uint8Array | paillierBigint.PrivateKey | number[];

  private constructor(
    cluster: Cluster,
    operations: Operations,
    threshold: number | undefined,
    material: Uint8Array | paillierBigint.PrivateKey | number[],
  ) {
    this.cluster = cluster;
    this.operations = operations;

    delete this.threshold; // Ensure there is no key in the object.
    if (threshold !== undefined) {
      this.threshold = threshold;
    }

    this.material = material;
  }

  /**
   * Return a secret key built according to what is specified in the supplied
   * cluster configuration and operation specification.
   */
  public static async generate(
    cluster: Cluster,
    operations: Operations,
    threshold: number | undefined = undefined,
    seed: Uint8Array | Buffer | string | undefined = undefined,
  ): Promise<SecretKey> {
    await sodium.ready;

    const cluster_ = new Cluster(cluster);
    const operations_ = new Operations(operations);
    const threshold_ = threshold;

    _validateKeyAttributes(cluster_, operations_, threshold_);

    // Assign placeholder value to accommodate the type. The operations
    // specification is valid at this point, so one of the branches
    // below will assign a value.
    let material_: Uint8Array | paillierBigint.PrivateKey | number[] = [];

    if (
      seed !== undefined &&
      !(seed instanceof Uint8Array) &&
      !Buffer.isBuffer(seed) &&
      typeof seed !== "string"
    ) {
      throw TypeError("seed must be string, Uint8Array, or Buffer");
    }

    // Normalize type of seed argument.
    const seedBytes: Uint8Array | undefined =
      seed === undefined
        ? undefined
        : typeof seed === "string"
          ? new TextEncoder().encode(seed)
          : new Uint8Array(seed);

    if (operations_.store) {
      // Symmetric key for encrypting the plaintext or the shares of a plaintext.
      material_ = await _randomBytes(
        sodium.crypto_secretbox_KEYBYTES,
        seedBytes,
      );
    } else if (operations_.match) {
      // Salt for  deterministic hashing of the plaintext.
      material_ = await _randomBytes(64, seedBytes);
    } else if (operations_.sum) {
      if (cluster_.nodes.length === 1) {
        // Paillier secret key for encrypting a plaintext numeric value.
        if (seed !== undefined) {
          throw Error(
            "seed-based derivation of summation-compatible secret keys " +
              "is not supported for single-node clusters",
          );
        }

        const { privateKey } =
          await paillierBigint.generateRandomKeys(_PAILLIER_KEY_LENGTH);

        // Discard cached prime factor attributes for consistency.
        material_ = new paillierBigint.PrivateKey(
          privateKey.lambda,
          privateKey.mu,
          privateKey.publicKey,
        );
      } else {
        // Distinct multiplicative mask for each share.
        material_ = [];
        for (let i = 0n; i < cluster_.nodes.length; i++) {
          const indexBytes = Buffer.alloc(8);
          indexBytes.writeBigInt64LE(i, 0);
          (material_ as number[]).push(
            Number(
              await _randomInteger(
                1n,
                _SECRET_SHARED_SIGNED_INTEGER_MODULUS - 1n,
                await _randomBytes(64, seedBytes, indexBytes),
              ),
            ),
          );
        }
      }
    }

    return new SecretKey(cluster_, operations_, threshold_, material_);
  }

  /**
   * Return a JSON-compatible object representation of this key instance.
   */
  public dump(): {
    cluster: Cluster;
    operations: Operations;
    threshold?: number;
    material:
      | string
      | { n: string; g: string; l: string; m: string }
      | number[];
  } {
    const object: {
      cluster: Cluster;
      operations: Operations;
      threshold?: number;
      material:
        | string
        | { n: string; g: string; l: string; m: string }
        | number[];
    } = {
      cluster: this.cluster,
      operations: this.operations,
      material: [],
    };

    delete object.threshold; // Ensure there is no key in the object.
    if (this.threshold !== undefined) {
      object.threshold = this.threshold;
    }

    if (
      Array.isArray(this.material) &&
      this.material.every((o) => typeof o === "number")
    ) {
      object.material = this.material.map((k) => k);
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
   * Return an instance built from a JSON-compatible object representation.
   */
  public static load(object: {
    cluster: Cluster;
    operations: Operations;
    threshold?: number;
    material:
      | string
      | { n: string; g: string; l: string; m: string }
      | number[];
  }): SecretKey {
    const cluster_ = new Cluster(object.cluster);
    const operations_ = new Operations(object.operations);
    const threshold_ = "threshold" in object ? object.threshold : undefined;

    _validateKeyAttributes(cluster_, operations_, threshold_);

    // Assign placeholder value to accommodate the type. The operations
    // specification is valid at this point, so one of the branches
    // below will assign a value.
    let material_: Uint8Array | paillierBigint.PrivateKey | number[] = [];

    if (operations_.store) {
      // A symmetric key (to encrypt individual values or secret shares)
      // is expected.
      if (typeof object.material !== "string") {
        throw TypeError(
          "operations specification requires key material to be a string",
        );
      }

      const buffer = _unpack(object.material as string);
      if (buffer.length !== 32) {
        throw Error("key material must have a length of 32 bytes");
      }

      material_ = buffer;
    } else if (operations_.match) {
      // A salt for hashing is expected.
      if (typeof object.material !== "string") {
        throw TypeError(
          "operations specification requires key material to be a string",
        );
      }

      const buffer = _unpack(object.material as string);
      if (buffer.length !== 64) {
        throw Error("key material must have a length of 64 bytes");
      }

      material_ = buffer;
    } else if (operations_.sum && cluster_.nodes.length === 1) {
      // Paillier secret key (to support summation-compatible encryption for
      // single-node clusters) is expected.
      if (!_isSimpleObject(object.material as object)) {
        throw new TypeError(
          "operations specification requires key material to be a simple object",
        );
      }

      const parameters = object.material as {
        n: string;
        g: string;
        l: string;
        m: string;
      };

      if (
        !(
          "l" in parameters &&
          "m" in parameters &&
          "n" in parameters &&
          "g" in parameters
        )
      ) {
        throw new Error("key material must contain all required parameters");
      }

      if (
        !(
          typeof parameters.l === "string" &&
          typeof parameters.m === "string" &&
          typeof parameters.n === "string" &&
          typeof parameters.g === "string"
        )
      ) {
        throw new TypeError("key material parameter values must be strings");
      }

      let l: bigint;
      let m: bigint;
      let n: bigint;
      let g: bigint;

      try {
        l = BigInt(parameters.l as string);
        m = BigInt(parameters.m as string);
        n = BigInt(parameters.n as string);
        g = BigInt(parameters.g as string);
      } catch (_) {
        throw Error(
          "key material parameter strings must be convertible to integer values",
        );
      }

      // Checking that the material contents (provided as integers represent
      // values that are within the correct range is the responsibility of the
      // constructor from the imported library.
      material_ = new paillierBigint.PrivateKey(
        l,
        m,
        new paillierBigint.PublicKey(n, g),
      );
    } else if (operations_.sum && cluster_.nodes.length > 1) {
      // Node-specific masks for secret shares (to support summation-compatible
      // encryption for multiple-node clusters) are expected.
      if (!Array.isArray(object.material)) {
        throw new TypeError(
          "operations specification requires key material to be an array",
        );
      }

      if (object.material.length !== cluster_.nodes.length) {
        throw new Error(
          "cluster configuration requires key material to have length " +
            cluster_.nodes.length,
        );
      }

      // Ensure the masks are integers and that the integers are in the right
      // range to represent multiplicative masks.
      if (!object.material.every((o) => typeof o === "number")) {
        throw new TypeError("key material must contain numbers");
      }

      if (!object.material.every((k) => Number.isInteger(k))) {
        throw new Error("key material must contain integer numbers");
      }

      if (
        !object.material.every(
          (k) => 1 <= k && k < _SECRET_SHARED_SIGNED_INTEGER_MODULUS,
        )
      ) {
        throw new Error(
          "key material must contain integer numbers within the correct range",
        );
      }

      material_ = object.material;
    }

    return new SecretKey(cluster_, operations_, threshold_, material_);
  }
}

/**
 * Data structure for representing all categories of cluster key instances.
 */
export class ClusterKey {
  cluster: Cluster;
  operations: Operations;
  threshold?: number;

  private constructor(
    cluster: Cluster,
    operations: Operations,
    threshold: number | undefined = undefined,
  ) {
    this.cluster = cluster;
    this.operations = operations;

    delete this.threshold; // Ensure there is no key in the object.
    if (threshold !== undefined) {
      this.threshold = threshold;
    }
  }

  /**
   * Return a cluster key built according to what is specified in the supplied
   * cluster configuration and operation specification.
   */
  public static async generate(
    cluster: Cluster,
    operations: Operations,
    threshold: number | undefined = undefined,
  ): Promise<ClusterKey> {
    const cluster_ = new Cluster(cluster);

    if (cluster_.nodes.length < 2) {
      throw new Error("cluster configuration must contain at least two nodes");
    }

    const operations_ = new Operations(operations);

    if (operations_.match) {
      throw new Error(
        "cluster keys cannot support matching-compatible encryption",
      );
    }

    const threshold_ = threshold;

    _validateKeyAttributes(cluster_, operations_, threshold_);

    return new ClusterKey(cluster_, operations_, threshold_);
  }

  /**
   * Return a JSON-compatible object representation of this key instance.
   */
  public dump(): {
    cluster: Cluster;
    operations: Operations;
    threshold?: number;
  } {
    const object: {
      cluster: Cluster;
      operations: Operations;
      threshold?: number;
    } = {
      cluster: this.cluster,
      operations: this.operations,
    };

    delete object.threshold; // Ensure there is no key in the object.
    if ("threshold" in this) {
      object.threshold = this.threshold;
    }

    return object;
  }

  /**
   * Return an instance built from a JSON-compatible object representation.
   */
  public static load(object: {
    cluster: Cluster;
    operations: Operations;
    threshold?: number;
  }): ClusterKey {
    const cluster_ = new Cluster(object.cluster);

    if (cluster_.nodes.length < 2) {
      throw new Error("cluster configuration must contain at least two nodes");
    }

    const operations_ = new Operations(object.operations);

    if (operations_.match) {
      throw new Error(
        "cluster keys cannot support matching-compatible encryption",
      );
    }

    const threshold_ = object.threshold;

    _validateKeyAttributes(cluster_, operations_, threshold_);

    if ("material" in object) {
      throw new Error("cluster keys cannot contain key material");
    }

    return new ClusterKey(cluster_, operations_, threshold_);
  }
}

/**
 * Data structure for representing all categories of public key instances.
 */
export class PublicKey {
  cluster: Cluster;
  operations: Operations;
  material: paillierBigint.PublicKey;

  /**
   * Return a public key built according to what is specified in the supplied
   * secret key.
   */
  private constructor(
    cluster: Cluster,
    operations: Operations,
    material: paillierBigint.PublicKey,
  ) {
    this.cluster = cluster;
    this.operations = operations;
    this.material = material;
  }

  /**
   * Return a public key built according to what is specified in the supplied
   * secret key.
   */
  public static async generate(secretKey: SecretKey): Promise<PublicKey> {
    // No internal validation of the supplied secret key is performed beyond
    // what is necessary for the generation of this public key. It is also
    // assumed that the encapsulated key from the Paillier cryptosystem library
    // has valid internal structure.

    if (!(secretKey instanceof SecretKey)) {
      throw new TypeError("secret key expected");
    }

    if (typeof secretKey.material !== "object") {
      throw new TypeError("secret key material must be an object");
    }

    if (!("publicKey" in secretKey.material)) {
      throw new Error("secret key must contain public key");
    }

    if (!(secretKey.material.publicKey instanceof paillierBigint.PublicKey)) {
      throw new TypeError(
        "secret key must contain public key of the correct type",
      );
    }

    return new PublicKey(
      secretKey.cluster,
      secretKey.operations,
      secretKey.material.publicKey,
    );
  }

  /**
   * Return a JSON-compatible object representation of this key instance.
   */
  public dump(): {
    cluster: Cluster;
    operations: Operations;
    material: { n: string; g: string };
  } {
    return {
      cluster: this.cluster,
      operations: this.operations,

      // Public key for Paillier encryption.
      material: {
        n: this.material.n.toString(),
        g: this.material.g.toString(),
      },
    };
  }

  /**
   * Return an instance built from a JSON-compatible object representation.
   */
  public static load(object: {
    cluster: Cluster;
    operations: Operations;
    material: { n: string; g: string };
  }): PublicKey {
    const cluster_ = new Cluster(object.cluster);

    if (cluster_.nodes.length !== 1) {
      throw new Error(
        "public keys are only supported for single-node clusters",
      );
    }

    const operations_ = new Operations(object.operations);

    if (!operations_.sum) {
      throw new Error("public keys can only support the sum operation");
    }

    if ("threshold" in object) {
      throw new Error("public keys cannot specify a threshold");
    }

    _validateKeyAttributes(cluster_, operations_);

    // Validate and normalize/wrap the key material.
    if (!_isSimpleObject(object.material)) {
      throw new TypeError("key material must be a simple object");
    }

    const parameters = object.material;

    if (!("n" in parameters && "g" in parameters)) {
      throw new Error("key material must contain all required parameters");
    }

    if (
      !(typeof parameters.n === "string" && typeof parameters.g === "string")
    ) {
      throw new TypeError("key material parameter values must be strings");
    }

    let n: bigint;
    let g: bigint;

    try {
      n = BigInt(object.material.n);
      g = BigInt(object.material.g);
    } catch (_) {
      throw Error(
        "key material parameter strings must be convertible to integer values",
      );
    }

    return new PublicKey(
      cluster_,
      operations_,

      // Checking that the material values are within the correct range is the
      // responsibility of the constructor from the imported library.
      new paillierBigint.PublicKey(n, g),
    );
  }
}

/**
 * Return the ciphertext obtained by using the supplied key to encrypt the
 * supplied plaintext.
 *
 * The supplied key determines what protocol is used to perform the encryption.
 * Invocations involving invalid argument values or types may throw an error.
 * The type of the `key` argument is checked. Incompatibilities between those
 * attribute values and the supplied `plaintext` argument are also detected.
 * However, the values associated with those attributes (such as the cluster
 * configuration, the cryptographic material associated with the supplied key,
 * interdependencies between these, and so on) are not checked for validity.
 */
export async function encrypt(
  key: SecretKey | ClusterKey | PublicKey,
  plaintext: number | bigint | string | Uint8Array,
): Promise<string | string[] | number[] | number[][]> {
  await sodium.ready;

  const error = new Error(
    "cannot encrypt the supplied plaintext using the supplied key",
  );

  // Local variables for representing the plaintext. These may or may not be
  // used depending on the supplied key and plaintext type.
  let buffer: Buffer;
  let bigInt: bigint | undefined;

  // Normalize the supplied plaintext.
  if (typeof plaintext === "number" || typeof plaintext === "bigint") {
    // Normalize, check, and encode integer plaintext.
    bigInt =
      typeof plaintext === "number" ? BigInt(Number(plaintext)) : plaintext;

    if (
      bigInt < _PLAINTEXT_SIGNED_INTEGER_MIN ||
      bigInt > _PLAINTEXT_SIGNED_INTEGER_MAX
    ) {
      throw new Error(
        "numeric plaintext must be a valid 32-bit signed integer",
      );
    }

    buffer = Buffer.from(_encode(bigInt));
  } else {
    // Encode a string or binary plaintext for storage or matching.
    buffer = Buffer.from(_encode(plaintext));

    if (buffer.length > _PLAINTEXT_STRING_BUFFER_LEN_MAX + 1) {
      const len = _PLAINTEXT_STRING_BUFFER_LEN_MAX;
      throw new Error(
        `string or binary plaintext must be at most ${len} bytes or fewer in length`,
      );
    }
  }

  // Encrypt a plaintext for storage and retrieval.
  if (key.operations.store) {
    // The data or secret shares of the data might or might not be encrypted
    // by a symmetric key (depending on the supplied key's parameters).
    let optionalEncrypt = (uint8Array: Uint8Array) => uint8Array;
    if ("material" in key) {
      const symmetricKey = key.material as Uint8Array;
      optionalEncrypt = (uint8Array) => {
        try {
          const nonce = sodium.randombytes_buf(
            sodium.crypto_secretbox_NONCEBYTES,
          );
          return _concat(
            nonce,
            sodium.crypto_secretbox_easy(uint8Array, nonce, symmetricKey),
          );
        } catch (_) {
          throw error;
        }
      };
    }

    // For single-node clusters, only a secret key can be used to encrypt for
    // storage. The data is encrypted using a symmetric key found in the
    // supplied secret key.
    if (key.cluster.nodes.length === 1) {
      return _pack(optionalEncrypt(new Uint8Array(buffer)));
    }

    // For multiple-node clusters and no threshold, a secret-shared plaintext
    // is obtained using XOR (with each share symmetrically encrypted in the
    // case of a secret key).
    if (!("threshold" in key)) {
      const shares: Uint8Array[] = [];
      let aggregate = Buffer.alloc(buffer.length, 0);
      for (let i = 0; i < key.cluster.nodes.length - 1; i++) {
        const mask = Buffer.from(sodium.randombytes_buf(buffer.length));
        aggregate = _xor(aggregate, mask);
        shares.push(optionalEncrypt(mask));
      }
      shares.push(optionalEncrypt(_xor(aggregate, buffer)));
      return shares.map(_pack);
    }

    // For multiple-node clusters and a threshold, the plaintext is converted
    // into secret shares using Shamir's secret sharing scheme (with each share
    // symmetrically encrypted in the case of a secret key).

    // Pad the buffer to ensure its length is a multiple of four.
    const padding = 4 - (buffer.length % 4);
    const padded = _concat(new Uint8Array(padding).fill(255), buffer);

    // Split into subarrays of length four.
    const subarrays = [];
    for (let i = 0; i < padded.length; i += 4) {
      subarrays.push(padded.subarray(i, i + 4));
    }

    // Build up shares of the plaintext where each share is actually a list of
    // shares (one such share per subarray of the plaintext).
    const sharesOfArray: bigint[][][] = [];
    for (let i = 0; i < key.cluster.nodes.length; i++) {
      sharesOfArray.push([]);
    }
    for (const subarray of subarrays) {
      const subarrayAsBigInt = _bigIntFromUint8Array(subarray);
      const subarrayAsShares: [bigint, bigint][] = await _shamirsShares(
        subarrayAsBigInt,
        key.cluster.nodes.length,
        _SECRET_SHARED_SIGNED_INTEGER_MODULUS,
        key.threshold,
      );
      for (let i = 0; i < subarrayAsShares.length; i++) {
        sharesOfArray[i].push(subarrayAsShares[i]);
      }
    }

    // Convert each share from a list (of subarray shares) representation into
    // a single integer representation.
    const shares = [];
    for (let i = 0; i < sharesOfArray.length; i++) {
      const shareOfArray = sharesOfArray[i];

      // Each Shamir's share has an index and a value component. The index
      // will not change within each share (assuming the share indices are
      // always the same and in the same order). Therefore, the index is
      // only stored once to reduce its overhead.
      const index = _bigIntToUint8Array(shareOfArray[0][0], 4);
      let shareOfArrayAsBytes = index;
      for (const subarrayShare of shareOfArray) {
        const value = _bigIntToUint8Array(subarrayShare[1], 5);
        shareOfArrayAsBytes = _concat(shareOfArrayAsBytes, value);
      }
      shares.push(_pack(optionalEncrypt(shareOfArrayAsBytes)));
    }

    return shares;
  }

  // Encrypt (i.e., hash) a plaintext for matching.
  if (key.operations.match) {
    // The deterministic salted hash of the encoded plaintext is the ciphertext.
    const hashed = await _sha512(
      _concat(
        (key as SecretKey).material as Uint8Array,
        new Uint8Array(buffer),
      ),
    );
    const ciphertext = _pack(hashed);

    // For multiple-node clusters, replicate the ciphertext for each node.
    if (key.cluster.nodes.length > 1) {
      return key.cluster.nodes.map((_) => ciphertext);
    }

    return ciphertext;
  }

  // Encrypt an integer plaintext in a summation-compatible way.
  if (key.operations.sum) {
    // Non-integer plaintexts cannot be encrypted for summation.
    if (bigInt === undefined) {
      throw new TypeError(
        "summation-compatible encryption requires a numeric plaintext",
      );
    }

    // For single-node clusters, the Paillier cryptosystem is used. Only a
    // Paillier secret or public key can be used to encrypt for summation.
    if (key.cluster.nodes.length === 1) {
      // Extract public key from secret key if a secret key was supplied and
      // rebuild the public key object for the Paillier library.
      let paillierPublicKey: paillierBigint.PublicKey;

      if ("material" in key && "publicKey" in (key.material as object)) {
        // Secret key was supplied.
        paillierPublicKey = (key.material as { publicKey: object })
          .publicKey as paillierBigint.PublicKey;
      } else {
        // Public key was supplied.
        paillierPublicKey = (key as PublicKey)
          .material as paillierBigint.PublicKey;
      }

      return paillierPublicKey
        .encrypt(bigInt + (bigInt < 0 ? paillierPublicKey.n : 0n))
        .toString(16);
    }

    // For multiple-node clusters and no threshold, additive secret sharing is used.
    if (!(typeof (key as SecretKey | ClusterKey).threshold === "number")) {
      const masks: bigint[] =
        "material" in key
          ? (key.material as number[]).map(BigInt)
          : key.cluster.nodes.map((_) => 1n);
      const shares: bigint[] = [];
      let total = BigInt(0);
      const quantity = key.cluster.nodes.length;
      for (let i = 0; i < quantity - 1; i++) {
        const share = await _randomInteger(
          0n,
          _SECRET_SHARED_SIGNED_INTEGER_MODULUS - 1n,
        );
        shares.push(
          _mod(masks[i] * share, _SECRET_SHARED_SIGNED_INTEGER_MODULUS),
        );
        total = _mod(total + share, _SECRET_SHARED_SIGNED_INTEGER_MODULUS);
      }
      shares.push(
        _mod(
          _mod(bigInt - total, _SECRET_SHARED_SIGNED_INTEGER_MODULUS) *
            BigInt(masks[quantity - 1]),
          _SECRET_SHARED_SIGNED_INTEGER_MODULUS,
        ),
      );

      return shares.map(Number);
    }

    // For multiple-node clusters and a threshold, Shamir's secret sharing is used.
    let shares = await _shamirsShares(
      bigInt,
      key.cluster.nodes.length,
      _SECRET_SHARED_SIGNED_INTEGER_MODULUS,
      (key as SecretKey | ClusterKey).threshold,
    );

    // For multiple-node clusters, additive secret sharing is used.
    const masks: bigint[] =
      "material" in key
        ? (key.material as number[]).map(BigInt)
        : key.cluster.nodes.map((_) => 1n);

    shares = shares.map(([x, y], i) => [
      x,
      _mod(y * masks[i], _SECRET_SHARED_SIGNED_INTEGER_MODULUS),
    ]);

    return shares.map(([x, y]) => [Number(x), Number(y)]) as [number, number][];
  }

  // The below should not occur unless the key's cluster or operations
  // information is malformed/missing or the plaintext is unsupported.
  throw error;
}

/**
 * Return the plaintext obtained by using the supplied key to decrypt the
 * supplied ciphertext.
 *
 * The supplied key determines what protocol is used to perform the decryption.
 * Invocations involving invalid argument values or types may throw an error.
 * The type of the `key` argument is checked. Incompatibilities between the
 * key's attribute values and the supplied `ciphertext` argument are detected.
 * However, the values associated with those attributes (such as the cluster
 * configuration, the cryptographic material associated with the supplied key,
 * interdependencies between these, and so on) are not checked for validity.
 */
export async function decrypt(
  key: SecretKey | ClusterKey,
  ciphertext: string | string[] | number[] | number[][],
): Promise<bigint | string | Uint8Array> {
  await sodium.ready;

  const error = new Error(
    "cannot decrypt the supplied ciphertext using the supplied key",
  );

  // Identify common (i.e., not operation-specific) incompatibilities between
  // the supplied key and ciphertext.
  if (key.cluster.nodes.length === 1) {
    if (typeof ciphertext !== "string") {
      throw new Error(
        "key requires a valid ciphertext from a single-node cluster",
      );
    }
  } else {
    // Key has a multiple-node cluster configuration.

    // Reject ciphertexts that are not compatible with multiple-node clusters.
    if (!Array.isArray(ciphertext)) {
      throw new Error(
        "key requires a valid ciphertext from a multiple-node cluster",
      );
    }

    // Reject share arrays that do not contain enough shares.
    if (
      ciphertext.length <
      (typeof key.threshold === "number"
        ? key.threshold
        : key.cluster.nodes.length)
    ) {
      throw new Error(
        "ciphertext must have enough shares for cluster size or threshold",
      );
    }
  }

  // Decrypt a value that was encrypted for storage and retrieval.
  if (key.operations.store) {
    // The plaintext or secret shares of the plaintext might or might not have
    // been encrypted by a symmetric key (depending on the supplied key).
    let optionalDecrypt = (uint8Array: Uint8Array) => uint8Array;
    if ("material" in key) {
      const symmetricKey = key.material as Uint8Array;
      optionalDecrypt = (uint8Array) => {
        try {
          const nonce = uint8Array.subarray(
            0,
            sodium.crypto_secretbox_NONCEBYTES,
          );
          const cipher = uint8Array.subarray(
            sodium.crypto_secretbox_NONCEBYTES,
          );
          return sodium.crypto_secretbox_open_easy(cipher, nonce, symmetricKey);
        } catch (_) {
          throw error;
        }
      };
    }

    // For single-node clusters, the plaintext is encrypted using a symmetric key.
    if (key.cluster.nodes.length === 1) {
      return _decode(optionalDecrypt(_unpack(ciphertext as string)));
    }

    // For multiple-node clusters, the ciphertext must be an array of shares
    // (each element being a Base64-encoded binary value). The quantity of
    // shares is already confirmed during the common checks above.
    if (Array.isArray(ciphertext)) {
      if (!ciphertext.every((share) => typeof share === "string")) {
        throw new TypeError(
          "secret shares must all be Base64-encoded binary values",
        );
      }
    }

    // Each share consists of Base64-encoded (possibly encrypted) binary data.
    const shares = (ciphertext as string[]).map(_unpack).map(optionalDecrypt);

    // For multiple-node clusters and no threshold, the plaintext is
    // secret-shared using XOR.
    if (!("threshold" in key)) {
      // Accept only arrays of XOR secret shares that all have the same length.
      if ([...new Set(shares.map((share) => share.length))].length !== 1) {
        throw Error("secret shares must have matching lengths");
      }

      // Build up encoded plaintext as `buffer`; its decoding is then returned.
      let buffer = Buffer.from(shares[0]);
      for (let i = 1; i < shares.length; i++) {
        buffer = Buffer.from(_xor(buffer, Buffer.from(shares[i])));
      }
      return _decode(buffer);
    }

    // For multiple-node clusters and a threshold, Shamir's secret sharing is
    // used to create a secret-shared plaintext.

    // Accept only sequences of shares having sufficient and matching lengths.
    const _lengths = shares.map((share) => share.length);
    /*if not (len(lengths) == 1 and lengths[0] >= 9):
        raise ValueError('secret shares must have sufficient and matching lengths')
    */

    // Build up encoded plaintext as `buffer`; its decoding is then returned.

    // Begin to extract the indices and values of the individual Shamir's
    // shares that were all concatenated together during encryption.
    const sharesOfPlaintext = [];
    const indices: bigint[] = []; // Ordered list of indices for the shares of the plaintext.
    for (const share of shares) {
      const valuesAsUin8Array = share.subarray(4);
      const arrayOfShamirsShares = [];
      for (let i = 0; i < valuesAsUin8Array.length; i += 5) {
        arrayOfShamirsShares.push(valuesAsUin8Array.subarray(i, i + 5));
      }
      sharesOfPlaintext.push(arrayOfShamirsShares);
      indices.push(_bigIntFromUint8Array(share.subarray(0, 4)));
    }
    const numberOfPlaintextSubarrays = sharesOfPlaintext[0].length;

    // Accumulator for assembling plaintext as an array of bytes.
    let buffer = new Uint8Array();

    // Iterate over subarrays making up the plaintext.
    for (let i = 0; i < numberOfPlaintextSubarrays; i++) {
      const subarrayShares: [bigint, bigint][] = [];
      for (let j = 0; j < sharesOfPlaintext.length; j++) {
        subarrayShares.push([
          indices[j],
          _bigIntFromUint8Array(sharesOfPlaintext[j][i]),
        ]);
      }
      const subarrayAsBigInt = _shamirsRecover(
        subarrayShares,
        _SECRET_SHARED_SIGNED_INTEGER_MODULUS,
      );
      buffer = _concat(buffer, _bigIntToUint8Array(subarrayAsBigInt, 4));
    }

    // Drop padding bytes (added during encryption so that byte count is a
    // multiple of four).
    while (buffer.length > 0 && buffer[0] === 255) {
      buffer = buffer.subarray(1);
    }

    return _decode(buffer);
  }

  // Decrypt a value that was encrypted in a summation-compatible way.
  if (key.operations.sum) {
    // For single-node clusters, the Paillier cryptosystem is used.
    if (key.cluster.nodes.length === 1) {
      const paillierPrivateKey = (key as SecretKey)
        .material as paillierBigint.PrivateKey;
      const plaintextFieldElement = paillierPrivateKey.decrypt(
        BigInt(`0x${ciphertext as string}`),
      );
      return (
        plaintextFieldElement -
        (plaintextFieldElement > _PLAINTEXT_SIGNED_INTEGER_MAX
          ? (paillierPrivateKey.publicKey as paillierBigint.PublicKey).n
          : 0n)
      );
    }

    // For multiple-node clusters and no threshold, additive secret sharing is used.
    if (!(typeof key.threshold === "number")) {
      // Accept only arrays of additive secret shares. Ciphertext type
      // and quantity of shares are already confirmed by common checks.
      if (Array.isArray(ciphertext)) {
        if (!ciphertext.every((share) => typeof share === "number")) {
          throw TypeError("secret shares must all be integers");
        }

        if (
          !ciphertext.every(
            (share) =>
              0 <= share && share <= _SECRET_SHARED_SIGNED_INTEGER_MODULUS,
          )
        ) {
          throw Error(
            "secret shares must all be nonnegative integers less than the modulus",
          );
        }
      }

      // Store the decryption result in `plaintext`.
      const inverseMasks: bigint[] =
        "material" in key
          ? (key.material as number[]).map((mask) => {
              return bcu.modPow(
                BigInt(mask),
                _SECRET_SHARED_SIGNED_INTEGER_MODULUS - 2n,
                _SECRET_SHARED_SIGNED_INTEGER_MODULUS,
              );
            })
          : key.cluster.nodes.map((_) => 1n);
      const shares = ciphertext as number[];
      let plaintext = BigInt(0);
      for (let i = 0; i < shares.length; i++) {
        const share = _mod(
          BigInt(shares[i]) * inverseMasks[i],
          _SECRET_SHARED_SIGNED_INTEGER_MODULUS,
        );
        plaintext = _mod(
          plaintext + share,
          _SECRET_SHARED_SIGNED_INTEGER_MODULUS,
        );
      }

      // Field elements in the "upper half" of the field represent negative
      // integers.
      if (plaintext > _PLAINTEXT_SIGNED_INTEGER_MAX) {
        plaintext -= _SECRET_SHARED_SIGNED_INTEGER_MODULUS;
      }

      return plaintext;
    }

    // For multiple-node clusters and a threshold, Shamir's secret sharing is used.

    // Accept only arrays of Shamir's secret shares (in integer form).
    // Ciphertext type and quantity of shares are already confirmed by common
    // checks.
    if (Array.isArray(ciphertext)) {
      if (!ciphertext.every((share) => Array.isArray(share))) {
        throw TypeError("secret shares must all be arrays");
      }

      if (!ciphertext.every((share) => share.length === 2)) {
        throw Error("secret shares must all have two components");
      }

      if (
        !ciphertext.every(
          (share) =>
            1 <= share[0] && share[0] < _SECRET_SHARED_SIGNED_INTEGER_MODULUS,
        ) ||
        [...new Set(ciphertext.map((share) => share[0]))].length !==
          ciphertext.length
      ) {
        throw Error(
          "secret share index components must be distinct positive " +
            "integers less than the modulus",
        );
      }

      if (
        !ciphertext.every(
          (share) =>
            0 <= share[1] && share[0] < _SECRET_SHARED_SIGNED_INTEGER_MODULUS,
        )
      ) {
        throw Error(
          "secret share value components must be nonnegative integers " +
            "less than the modulus",
        );
      }
    }

    // Store the decryption result in `plaintext`.
    const inverseMasks: bigint[] =
      "material" in key
        ? (key.material as number[]).map((mask) => {
            return bcu.modPow(
              BigInt(mask),
              _SECRET_SHARED_SIGNED_INTEGER_MODULUS - 2n,
              _SECRET_SHARED_SIGNED_INTEGER_MODULUS,
            );
          })
        : key.cluster.nodes.map((_) => 1n);

    const shares: [bigint, bigint][] = (ciphertext as [number, number][]).map(
      ([x, y], _i) => [
        BigInt(x),
        _mod(
          inverseMasks[x - 1] * BigInt(y),
          _SECRET_SHARED_SIGNED_INTEGER_MODULUS,
        ),
      ],
    );

    let plaintext: bigint = _shamirsRecover(
      shares,
      _SECRET_SHARED_SIGNED_INTEGER_MODULUS,
    );

    // Field elements in the "upper half" of the field represent negative
    // integers.
    if (plaintext > _PLAINTEXT_SIGNED_INTEGER_MAX) {
      plaintext -= _SECRET_SHARED_SIGNED_INTEGER_MODULUS;
    }

    return plaintext;
  }

  // The below should not occur unless the key's cluster or operations
  // information is malformed/missing or the ciphertext is unsupported.
  throw error;
}

/**
 * Convert an object that may contain ciphertexts intended for multi-node
 * clusters into secret shares of that object. Shallow copies are created
 * whenever possible.
 */
export function allot(
  document: boolean | number | string | object | null,
): (boolean | number | string | object | null)[] {
  // Values and `null` are base cases.
  if (
    typeof document === "boolean" ||
    typeof document === "number" ||
    typeof document === "string" ||
    document === null
  ) {
    return [document];
  }

  if (Array.isArray(document)) {
    const results = (document as object[]).map(allot);

    // Determine the number of shares that must be created.
    let multiplicity = 1;
    for (let i = 0; i < results.length; i++) {
      const result = results[i];
      if (result.length !== 1) {
        if (multiplicity === 1) {
          multiplicity = result.length;
        } else if (multiplicity !== result.length) {
          throw new Error("number of shares in subdocument is not consistent");
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

  if (document instanceof Object) {
    // Document contains shares obtained from the `encrypt` function
    // that must be allotted to nodes.
    if ("%allot" in document) {
      if (Object.keys(document).length !== 1) {
        throw new Error("allotment must only have one key");
      }

      const items = document["%allot"] as object[];
      if (
        items.every((item) => typeof item === "number") ||
        items.every((item) => typeof item === "string")
      ) {
        // Simple allotment with a single ciphertext.
        const shares = [];
        for (let i = 0; i < items.length; i++) {
          shares.push({ "%share": items[i] });
        }
        return shares;
      }

      // More complex allotment with nested lists of ciphertexts.
      const sharesArrays = allot(
        items.map((item) => {
          return { "%allot": item };
        }),
      );
      const shares = [];
      for (let i = 0; i < sharesArrays.length; i++) {
        const sharesCurrent: object[] = sharesArrays[i] as object[];
        shares.push({
          "%share": sharesCurrent.map(
            (share) => (share as { "%share": object })["%share"],
          ),
        });
      }
      return shares;
    }

    // Document is a general-purpose key-value mapping.
    const existing = document as { [k: string]: object };
    const results: { [k: string]: object } = {};
    let multiplicity = 1;
    for (const key in existing) {
      const result = allot(existing[key]);
      results[key] = result;
      if (result.length !== 1) {
        if (multiplicity === 1) {
          multiplicity = result.length;
        } else if (multiplicity !== result.length) {
          throw new Error("number of shares in subdocument is not consistent");
        }
      }
    }

    // Create and return the appropriate number of document shares.
    const shares = [];
    for (let i = 0; i < multiplicity; i++) {
      const share: { [k: string]: object } = {};
      for (const key in results) {
        const resultsForKey = results[key] as object[];
        share[key] = resultsForKey[resultsForKey.length === 1 ? 0 : i];
      }
      shares.push(share);
    }

    return shares;
    /* v8 ignore next */ // The closing brace is unreachable due to `return`.
  }

  /* v8 ignore next 4 */ // Type checking ensures that the below is unreachable.
  throw new TypeError(
    "boolean, number, string, array, null, or object expected",
  );
}

/**
 * Convert an array of compatible secret share objects into a single object
 * that deduplicates matching plaintext leaf values and recombines matching
 * secret share leaf values.
 */
export async function unify(
  secretKey: SecretKey,
  documents: (boolean | number | string | object | null)[],
  ignore: string[] = ["_created", "_updated"],
): Promise<
  | (boolean | number | string | object | null)
  | (boolean | number | string | object | null)[]
> {
  if (documents.length === 1) {
    return documents[0];
  }

  if (documents.every((document) => Array.isArray(document))) {
    const length = documents[0].length;
    if (documents.every((document) => document.length === length)) {
      const results = [];
      for (let i = 0; i < length; i++) {
        const result = await unify(
          secretKey,
          documents.map((document) => document[i]),
          ignore,
        );
        results.push(result);
      }
      return results;
    }
  }

  if (documents.every((document) => document instanceof Object)) {
    // Documents are shares.
    if (documents.every((document) => "%share" in document)) {
      // Simple document shares.
      if (
        documents.every((document) => typeof document["%share"] === "number") ||
        documents.every((document) => typeof document["%share"] === "string")
      ) {
        const shares = documents.map((document) => document["%share"]);
        const decrypted = decrypt(secretKey, shares as string[] | number[]);
        return decrypted as object;
      }

      // Document shares consisting of nested lists of shares.
      const unwrapped: object[][] = [];
      for (let i = 0; i < documents.length; i++) {
        unwrapped.push(documents[i]["%share"] as object[]);
      }
      const length = unwrapped[0].length;
      const results = [];
      for (let i = 0; i < length; i++) {
        const shares = [];
        for (let j = 0; j < documents.length; j++) {
          shares.push({ "%share": unwrapped[j][i] });
        }
        results.push(await unify(secretKey, shares, ignore));
      }
      return results;
    }

    // Documents are general-purpose key-value mappings.
    const keys: string[] = Object.keys(documents[0]);
    if (
      documents.every((document) => _equalKeys(keys, Object.keys(document)))
    ) {
      const results: {
        [k: string]: boolean | number | string | object | null;
      } = {};
      for (const key in documents[0]) {
        // For ignored keys, unification is not performed and they are
        // omitted from the results.
        if (ignore.indexOf(key) === -1) {
          const result = await unify(
            secretKey,
            documents.map(
              (document) => (document as { [k: string]: object })[key],
            ),
            ignore,
          );
          results[key] = result;
        }
      }
      return results;
    }
  }

  // Base case: all documents must be equivalent.
  let allValuesEqual = true;
  for (let i = 1; i < documents.length; i++) {
    allValuesEqual &&= documents[0] === documents[i];
  }
  if (allValuesEqual) {
    return documents[0];
  }

  throw new Error("array of compatible document shares expected");
}
