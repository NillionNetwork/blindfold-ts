/**
 * TypeScript library for working with encrypted data within nilDB queries
 * and replies.
 */
import * as bcu from "bigint-crypto-utils";
import sodium from "libsodium-wrappers-sumo";
import * as paillierBigint from "paillier-bigint";

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
const _SECRET_SHARED_SIGNED_INTEGER_MODULUS = 2n ** 32n + 15n;

/**
 * Maximum length of plaintext string values that can be encrypted.
 */
const _PLAINTEXT_STRING_BUFFER_LEN_MAX = 4096;

/**
 * Mathematically standard modulus operator.
 */
function _mod(n: bigint, m: bigint): bigint {
  return (((n < 0 ? n + m : n) % m) + m) % m;
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
 * Helper function to compare two arrays of strings.
 */
function _equalKeys(a: Array<string>, b: Array<string>) {
  const zip = (a: Array<string>, b: Array<string>) =>
    a.map((k, i) => [k, b[i]]);
  return zip(a, b).every((pair) => pair[0] === pair[1]);
}

/**
 * Return a SHA-512 hash of the supplied string.
 */
async function _sha512(bytes: Uint8Array): Promise<Uint8Array> {
  const buffer = await crypto.subtle.digest("SHA-512", bytes);
  return new Uint8Array(buffer);
}

/**
 * Return entries in an indexed sequence of seeds derived from a base seed.
 */
async function _seeds(seed: Uint8Array, index: bigint): Promise<Uint8Array> {
  if (index < 0 || index >= 2n ** 64n) {
    throw new RangeError("index must be a 64-bit unsigned integer value");
  }

  const buffer = Buffer.alloc(8);
  buffer.writeBigInt64LE(index, 0);
  return await _sha512(_concat(seed, new Uint8Array(buffer)));
}

/**
 * Return a random byte sequence of the specified length (using the seed if one
 * is supplied).
 */
async function _randomBytes(
  length: number,
  seed: Uint8Array | null = null,
): Promise<Uint8Array> {
  await sodium.ready;

  if (seed !== null) {
    let bytes = new Uint8Array();
    const iterations: number =
      Math.floor(length / 64) + (length % 64 > 0 ? 1 : 0);
    for (let i = 0n; i < iterations; i++) {
      bytes = _concat(bytes, await _seeds(seed, i));
    }
    return bytes.subarray(0, length);
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
  seed: Uint8Array | null = null,
): Promise<bigint> {
  if (minimum < 0 || minimum > 1) {
    throw new RangeError("minimum must be 0 or 1");
  }

  if (maximum <= minimum || maximum >= _SECRET_SHARED_SIGNED_INTEGER_MODULUS) {
    throw new RangeError(
      "maximum must be greater than the minimum and less than the modulus",
    );
  }

  const range = maximum - minimum;
  let integer = null;
  let index = 0n;
  while (integer === null || integer > range) {
    const uint8Array = await _randomBytes(
      8,
      seed !== null ? await _seeds(seed, index) : null,
    );
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
 * Encode an integer or string as a byte array. The encoding includes
 * information about the type of the value in the first byte (to enable
 * decoding without any additional context).
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
 * Decode a byte array back into an integer or string value.
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
 * Data structure for representing all categories of secret key instances.
 */
class SecretKey {
  material?: object | number;
  cluster: Cluster;
  operations: Operations;

  protected constructor(cluster: Cluster, operations: Operations) {
    if (cluster.nodes === undefined || cluster.nodes.length < 1) {
      throw new TypeError(
        "cluster configuration must contain at least one node",
      );
    }

    if (
      Object.keys(operations).length !== 1 ||
      (!operations.store && !operations.match && !operations.sum)
    ) {
      throw new TypeError(
        "operation specification must enable exactly one operation",
      );
    }

    this.material = {};
    this.cluster = cluster;
    this.operations = operations;
  }

  /**
   * Return a secret key built according to what is specified in the supplied
   * cluster configuration and operation specification.
   */
  public static async generate(
    cluster: Cluster,
    operations: Operations,
    seed: Uint8Array | Buffer | string | null = null,
  ): Promise<SecretKey> {
    await sodium.ready;

    // Normalize type of seed argument.
    const seedBytes: Uint8Array | null =
      seed === null
        ? null
        : typeof seed === "string"
          ? new TextEncoder().encode(seed)
          : new Uint8Array(seed);

    const secretKey = new SecretKey(cluster, operations);

    if (secretKey.operations.store) {
      // Symmetric key for encrypting the plaintext or the shares of a plaintext.
      secretKey.material = await _randomBytes(
        sodium.crypto_secretbox_KEYBYTES,
        seedBytes,
      );
    }

    if (secretKey.operations.match) {
      // Salt for  deterministic hashing of the plaintext.
      secretKey.material = await _randomBytes(64, seedBytes);
    }

    if (secretKey.operations.sum) {
      if (secretKey.cluster.nodes.length === 1) {
        // Paillier secret key for encrypting a plaintext numeric value.
        if (seed !== null) {
          throw Error(
            "seed-based derivation of summation-compatible keys " +
              "is not supported for single-node clusters",
          );
        }
        const { privateKey } = await paillierBigint.generateRandomKeys(2048);
        secretKey.material = privateKey;
      } else {
        // Distinct multiplicative mask for each additive share.
        secretKey.material = [];
        for (let i = 0n; i < secretKey.cluster.nodes.length; i++) {
          const seedIteration =
            seedBytes === null ? null : await _seeds(seedBytes, i);
          (secretKey.material as Array<number>).push(
            Number(
              await _randomInteger(
                1n,
                _SECRET_SHARED_SIGNED_INTEGER_MODULUS - 1n,
                seedIteration,
              ),
            ),
          );
        }
      }
    }
    return secretKey;
  }

  /**
   * Return a JSON-compatible object representation of this key instance.
   */
  public dump(): object {
    const object = {
      material: {},
      cluster: this.cluster,
      operations: this.operations,
    };

    if (
      Array.isArray(this.material) &&
      this.material.every((o) => typeof o === "number")
    ) {
      object.material = this.material;
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

    if (
      Array.isArray(object.material) &&
      object.material.every((o) => typeof o === "number")
    ) {
      secretKey.material = object.material;
    } else if (typeof object.material === "string") {
      secretKey.material = _unpack(object.material);
    } else {
      const material = object.material as object;

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
 * Data structure for representing all categories of cluster key instances.
 */
class ClusterKey extends SecretKey {
  protected constructor(cluster: Cluster, operations: Operations) {
    super(cluster, operations);
    if (cluster.nodes.length < 2) {
      throw new TypeError(
        "cluster configuration must contain at least two nodes",
      );
    }

    // biome-ignore lint: Attribute must not exist in object.
    delete this.material;

    this.cluster = cluster;
    this.operations = operations;
  }

  /**
   * Return a cluster key built according to what is specified in the supplied
   * cluster configuration and operation specification.
   */
  public static async generate(
    cluster: Cluster,
    operations: Operations,
  ): Promise<ClusterKey> {
    return new ClusterKey(cluster, operations);
  }

  /**
   * Return a JSON-compatible object representation of this key instance.
   */
  public dump(): object {
    return {
      cluster: this.cluster,
      operations: this.operations,
    };
  }

  /**
   * Return an instance built from a JSON-compatible object representation.
   */
  public static load(object: object): ClusterKey {
    if (!("cluster" in object && "operations" in object)) {
      throw new TypeError("invalid object representation of a cluster key");
    }

    return new ClusterKey(
      object.cluster as Cluster,
      object.operations as Operations,
    );
  }
}

/**
 * Data structure for representing all categories of public key instances.
 */
class PublicKey {
  material: object;
  cluster: Cluster;
  operations: Operations;

  private constructor(secretKey: SecretKey) {
    this.cluster = secretKey.cluster;
    this.operations = secretKey.operations;

    if (
      typeof secretKey.material === "object" &&
      "publicKey" in secretKey.material &&
      secretKey.material.publicKey instanceof paillierBigint.PublicKey
    ) {
      this.material = secretKey.material.publicKey;
    } else {
      throw new TypeError("cannot create public key for supplied secret key");
    }
  }

  /**
   * Return a public key built according to what is specified in the supplied
   * secret key.
   */
  public static async generate(secretKey: SecretKey): Promise<PublicKey> {
    return new PublicKey(secretKey);
  }

  /**
   * Return a JSON-compatible object representation of this key instance.
   */
  public dump(): object {
    const object = {
      material: {},
      cluster: this.cluster,
      operations: this.operations,
    };

    if (
      typeof this.material === "object" &&
      "n" in this.material &&
      "g" in this.material
    ) {
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
   * Return an instance built from a JSON-compatible object representation.
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
 * Return the ciphertext obtained by using the supplied key to encrypt the
 * supplied plaintext.
 */
async function encrypt(
  key: PublicKey | SecretKey,
  plaintext: number | bigint | string,
): Promise<string | string[] | number[]> {
  await sodium.ready;

  const error = new Error(
    "cannot encrypt the supplied plaintext using the supplied key",
  );

  // The values below may be used (depending on the plaintext type and the specific
  // kind of encryption being invoked).
  let buffer: Buffer = Buffer.from(new Uint8Array());
  let bigInt = 0n;

  // Ensure the supplied plaintext is of one of the supported types, check that the
  // value satisfies the constraints, and (if applicable) perform standard conversion
  // and encoding of the plaintext.
  if (typeof plaintext === "number" || typeof plaintext === "bigint") {
    // Encode an integer plaintext.
    bigInt =
      typeof plaintext === "number" ? BigInt(Number(plaintext)) : plaintext;
    buffer = Buffer.from(_encode(bigInt));

    if (
      bigInt < _PLAINTEXT_SIGNED_INTEGER_MIN ||
      bigInt > _PLAINTEXT_SIGNED_INTEGER_MAX
    ) {
      throw new TypeError(
        "numeric plaintext must be a valid 32-bit signed integer",
      );
    }
  } else {
    // Encode a string plaintext.
    buffer = Buffer.from(_encode(plaintext));

    if (buffer.length > _PLAINTEXT_STRING_BUFFER_LEN_MAX) {
      const len = _PLAINTEXT_STRING_BUFFER_LEN_MAX;
      throw new TypeError(
        `string plaintext must be possible to encode in ${len} bytes or fewer`,
      );
    }
  }

  // Encrypt a plaintext for storage and retrieval.
  if (key.operations.store) {
    // A symmetric key is used to encrypt the binary plaintext or the secret
    // shares thereof.
    const secretKey = key as SecretKey;
    let optionalEncrypt = (uint8Array: Uint8Array) => uint8Array;
    if ("material" in secretKey) {
      const symmetricKey = secretKey.material as Uint8Array;
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

    // For single-node clusters, the plaintext is encrypted using a symmetric key.
    if (key.cluster.nodes.length === 1) {
      return _pack(optionalEncrypt(new Uint8Array(buffer)));
    }

    // For multiple-node clusters, the plaintext is secret-shared using XOR
    // (with each share symmetrically encrypted in the case of a secret key).
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

  // Encrypt (i.e., hash) a plaintext for matching.
  if (key.operations.match) {
    // The deterministic salted hash of the encoded plaintext is the ciphertext.
    const secretKey = key as SecretKey;
    const hashed = await _sha512(
      _concat(secretKey.material as Uint8Array, new Uint8Array(buffer)),
    );
    const ciphertext = _pack(hashed);

    if (key.cluster.nodes.length > 1) {
      // For multiple-node clusters, replicate the ciphertext for each node.
      return key.cluster.nodes.map((_) => ciphertext);
    }

    return ciphertext;
  }

  // Encrypt an integer plaintext in a summation-compatible way.
  if (key.operations.sum) {
    // Only 32-bit signed integer plaintexts are supported.
    if (
      !(typeof plaintext === "number" && Number.isInteger(plaintext)) &&
      !(typeof plaintext === "bigint")
    ) {
      throw new TypeError(
        "plaintext to encrypt for sum operation must be integer number or bigint",
      );
    }

    // For single-node clusters, the Paillier cryptosystem is used.
    if (key.cluster.nodes.length === 1) {
      // Extract public key from secret key if a secret key was supplied and rebuild the
      // public key object for the Paillier library.
      let paillierPublicKey: paillierBigint.PublicKey;

      if ("publicKey" in (key.material as object)) {
        // Secret key was supplied.
        paillierPublicKey = (key.material as { publicKey: object })
          .publicKey as paillierBigint.PublicKey;
      } else {
        // Public key was supplied.
        paillierPublicKey = (key as PublicKey)
          .material as paillierBigint.PublicKey;
      }

      return paillierPublicKey
        .encrypt(bigInt - _PLAINTEXT_SIGNED_INTEGER_MIN)
        .toString(16);
    }

    // For multiple-node clusters, additive secret sharing is used.
    const secretKey = key as SecretKey;
    const masks: bigint[] =
      "material" in secretKey
        ? (secretKey.material as number[]).map(BigInt)
        : secretKey.cluster.nodes.map((_) => 1n);
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

  // The below should not occur unless the key's cluster or operations
  // information is malformed/missing or the plaintext is unsupported.
  throw error;
}

/**
 * Return the plaintext obtained by using the supplied key to decrypt the
 * supplied ciphertext.
 */
async function decrypt(
  secretKey: SecretKey,
  ciphertext: string | string[] | number[],
): Promise<bigint | string> {
  await sodium.ready;

  const error = new TypeError(
    "cannot decrypt the supplied ciphertext using the supplied key",
  );

  // Confirm that the secret key and ciphertext have compatible cluster
  // specifications.
  if (secretKey.cluster.nodes.length === 1) {
    if (typeof ciphertext !== "string") {
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
        "secret key requires a valid ciphertext from a multiple-node cluster",
      );
    }

    if (secretKey.cluster.nodes.length !== ciphertext.length) {
      throw new TypeError(
        "secret key and ciphertext must have the same associated cluster size",
      );
    }
  }

  // Decrypt a value that was encrypted for storage and retrieval.
  if (secretKey.operations.store) {
    // A symmetric key is used to encrypt the binary plaintext or the secret
    // shares thereof.
    let optionalDecrypt = (uint8Array: Uint8Array) => uint8Array;
    if ("material" in secretKey) {
      const symmetricKey = secretKey.material as Uint8Array;
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
    if (secretKey.cluster.nodes.length === 1) {
      return _decode(optionalDecrypt(_unpack(ciphertext as string)));
    }

    // For multiple-node clusters, the plaintext is secret-shared using XOR
    // (with each share symmetrically encrypted in the case of a secret key).
    const shares = (ciphertext as string[]).map(_unpack).map(optionalDecrypt);
    let buffer = Buffer.from(shares[0]);
    for (let i = 1; i < shares.length; i++) {
      buffer = Buffer.from(_xor(buffer, Buffer.from(shares[i])));
    }
    return _decode(buffer);
  }

  // Decrypt a value that was encrypted in a summation-compatible way.
  if (secretKey.operations.sum) {
    // For single-node clusters, the Paillier cryptosystem is used.
    if (secretKey.cluster.nodes.length === 1) {
      const paillierPrivateKey =
        secretKey.material as paillierBigint.PrivateKey;
      return (
        paillierPrivateKey.decrypt(BigInt(`0x${ciphertext as string}`)) +
        _PLAINTEXT_SIGNED_INTEGER_MIN
      );
    }

    // For multiple-node clusters, additive secret sharing is used.
    const inverseMasks: bigint[] =
      "material" in secretKey
        ? (secretKey.material as number[]).map((mask) => {
            return bcu.modPow(
              BigInt(mask),
              _SECRET_SHARED_SIGNED_INTEGER_MODULUS - 2n,
              _SECRET_SHARED_SIGNED_INTEGER_MODULUS,
            );
          })
        : secretKey.cluster.nodes.map((_) => 1n);
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

  throw error;
}

/**
 * Convert an object that may contain ciphertexts intended for multi-node
 * clusters into secret shares of that object. Shallow copies are created
 * whenever possible.
 */
function allot(document: object): object[] {
  // Values and `null` are base cases.
  if (
    typeof document === "number" ||
    typeof document === "boolean" ||
    typeof document === "string" ||
    document === null
  ) {
    return [document];
  }

  if (Array.isArray(document)) {
    const results = (document as Array<object>).map(allot);

    // Determine the number of shares that must be created.
    let multiplicity = 1;
    for (let i = 0; i < results.length; i++) {
      const result = results[i];
      if (result.length !== 1) {
        if (multiplicity === 1) {
          multiplicity = result.length;
        } else if (multiplicity !== result.length) {
          throw new TypeError(
            "number of shares in subdocument is not consistent",
          );
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
    if ("$allot" in document) {
      if (Object.keys(document).length !== 1) {
        throw new TypeError("allotment must only have one key");
      }

      const items = document.$allot as Array<object>;
      if (
        items.every((item) => typeof item === "number") ||
        items.every((item) => typeof item === "string")
      ) {
        // Simple allotment with a single ciphertext.
        const shares = [];
        for (let i = 0; i < items.length; i++) {
          shares.push({ $share: items[i] });
        }
        return shares;
      }

      // More complex allotment with nested lists of ciphertexts.
      const sharesArrays = allot(
        items.map((item) => {
          return { $allot: item };
        }),
      );
      const shares = [];
      for (let i = 0; i < sharesArrays.length; i++) {
        const sharesCurrent: Array<object> = sharesArrays[i] as Array<object>;
        shares.push({
          $share: sharesCurrent.map(
            (share) => (share as { $share: object }).$share,
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
          throw new TypeError(
            "number of shares in subdocument is not consistent",
          );
        }
      }
    }

    // Create and return the appropriate number of document shares.
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

  throw new TypeError(
    "number, boolean, string, array, null, or object expected",
  );
}

/**
 * Convert an array of compatible secret share objects into a single object
 * that deduplicates matching plaintext leaf values and recombines matching
 * secret share leaf values.
 */
async function unify(
  secretKey: SecretKey,
  documents: object[],
  ignore: string[] = ["_created", "_updated"],
): Promise<object | Array<object>> {
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
    if (documents.every((document) => "$share" in document)) {
      // Simple document shares.
      if (
        documents.every((document) => typeof document.$share === "number") ||
        documents.every((document) => typeof document.$share === "string")
      ) {
        const shares = documents.map((document) => document.$share);
        const decrypted = decrypt(secretKey, shares as string[] | number[]);
        return decrypted as object;
      }

      // Document shares consisting of nested lists of shares.
      const unwrapped: Array<Array<object>> = [];
      for (let i = 0; i < documents.length; i++) {
        unwrapped.push(documents[i].$share as Array<object>);
      }
      const length = unwrapped[0].length;
      const results = [];
      for (let i = 0; i < length; i++) {
        const shares = [];
        for (let j = 0; j < documents.length; j++) {
          shares.push({ $share: unwrapped[j][i] });
        }
        results.push(await unify(secretKey, shares, ignore));
      }
      return results;
    }

    // Documents are general-purpose key-value mappings.
    const keys: Array<string> = Object.keys(documents[0]);
    const zip = (a: Array<string>, b: Array<string>) =>
      a.map((k, i) => [k, b[i]]);
    if (
      documents.every((document) => _equalKeys(keys, Object.keys(document)))
    ) {
      const results: { [k: string]: object } = {};
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

  throw new TypeError("array of compatible document shares expected");
}

/**
 * Export library wrapper.
 */
export const nilql = {
  SecretKey,
  ClusterKey,
  PublicKey,
  encrypt,
  decrypt,
  allot,
  unify,
} as const;
