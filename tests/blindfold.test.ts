/**
 * Functional and algebraic unit tests for primitives.
 * Test suite containing functional unit tests for the exported primitives,
 * as well as unit tests confirming algebraic relationships among primitives.
 */

import type * as paillierBigint from "paillier-bigint";
import { describe, expect, test } from "vitest";
import * as blindfold from "#/lib";

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
 * Seeds used for tests confirming that key generation from seeds is consistent.
 */
const seedValues = [
  "012345678901234567890123456789012345678901234567890123456789",
  new TextEncoder().encode(
    "012345678901234567890123456789012345678901234567890123456789",
  ),
  Buffer.from(
    new TextEncoder().encode(
      "012345678901234567890123456789012345678901234567890123456789",
    ),
  ),
];

// biome-ignore format: Concise list of test case parameter values.
const plaintextIntegerValues = [
  _PLAINTEXT_SIGNED_INTEGER_MIN, -123n, 0n, 123n, _PLAINTEXT_SIGNED_INTEGER_MAX,
  Number(_PLAINTEXT_SIGNED_INTEGER_MIN), -123, 0, 123, Number(_PLAINTEXT_SIGNED_INTEGER_MAX),
] as (number | bigint | string | Uint8Array)[];

/**
 * Precomputed constant that can be reused to reduce running time of tests.
 */
const secretKeyForSumWithOneNode = await blindfold.SecretKey.generate(
  cluster(1),
  { sum: true },
);

/**
 * Convert an object that may contain `bigint` values to JSON (because
 * `JSON.stringify` cannot convert `bigint` values automatically).
 */
function toJSON(o: boolean | number | string | null | object): string {
  return JSON.stringify(o, (_, v) =>
    typeof v === "bigint" ? v.toString() : v,
  );
}

/**
 * Mathematically standard modulus operator.
 */
function mod(n: bigint, m: bigint): bigint {
  return (((n < 0 ? n + m : n) % m) + m) % m;
}

/**
 * Add two sets of Shamir's shares componentwise, assuming they use the same
 * indices.
 */
function shamirsAdd(
  sharesA: [number, number][],
  sharesB: [number, number][],
  prime: bigint,
): [number, number][] {
  if (sharesA.length !== sharesB.length) {
    throw new Error("sequences of shares must have the same length");
  }

  return sharesA.map(([i, v], index) => {
    const [j, w] = sharesB[index];
    if (i !== j) {
      throw new Error("shares in each sequence must have the same indices");
    }
    return [i, Number(mod(BigInt(v) + BigInt(w), BigInt(prime)))];
  });
}

/**
 * Multiply a set of Shamir's shares componentwise.
 */
function shamirsMul(
  shares: [number, number][],
  scalar: number,
  prime: bigint,
): [number, number][] {
  return shares.map(([i, v], _) => {
    return [i, Number(mod(BigInt(v) * BigInt(scalar), BigInt(prime)))];
  });
}

/**
 * Convert a large binary test output into a short hash.
 */
async function toHashBase64(output: Uint8Array | number[]): Promise<string> {
  let uint8Array: Uint8Array;

  if (Array.isArray(output) && output.every((n) => typeof n === "number")) {
    const buffer = Buffer.alloc(8 * output.length);
    for (let i = 0; i < output.length; i++) {
      buffer.writeBigInt64LE(BigInt(output[i]), i * 8);
    }
    uint8Array = new Uint8Array(buffer);
  } else {
    uint8Array = output as Uint8Array;
  }

  return Buffer.from(
    new Uint8Array(await crypto.subtle.digest("SHA-256", uint8Array)),
  ).toString("base64");
}

/**
 * Compare two arrays of object keys (i.e., strings).
 */
function equalKeys(a: string[], b: string[]): boolean {
  const zip = (a: string[], b: string[]) => a.map((k, i) => [k, b[i]]);
  return zip(a, b).every((pair) => pair[0] === pair[1]);
}

/**
 * Return a cluster configuration of the specified size.
 */
function cluster(size: number): blindfold.Cluster {
  const nodes = [];
  for (let i = 0; i < size; i++) {
    nodes.push({});
  }
  return new blindfold.Cluster({ nodes: nodes });
}

/**
 * Function to detect when a `try` block did not throw an expected error.
 */
function expectThrow() {
  throw new Error("expected test to throw error");
}

/**
 * Test that the exported classes and functions match the expected API.
 */
describe("namespace", () => {
  test("blindfold API has all methods", () => {
    expect(blindfold).not.toBeNull();
    const methods = Object.getOwnPropertyNames(blindfold);
    expect(methods).toEqual(
      expect.arrayContaining([
        // API symbols that should be available to users upon module import.
        "Cluster",
        "Operations",
        "SecretKey",
        "ClusterKey",
        "PublicKey",
        "encrypt",
        "decrypt",
        "allot",
        "unify",
      ]),
    );
  });
});

/**
 * Tests of utility functions.
 */
describe("errors that can occur within utility functions", () => {
  test("errors that can occur within utility functions", async () => {
    const _temporary = globalThis.crypto;
    try {
      // @ts-ignore // Simulate an environment without the Web Crypto API.
      delete globalThis.crypto;

      const secretKey = await blindfold.SecretKey.generate(cluster(1), {
        match: true,
      });
      await blindfold.encrypt(secretKey, "abc");
      expectThrow();
    } catch (e) {
      expect(e).toStrictEqual(Error("Web Crypto API is not available"));
      globalThis.crypto = _temporary;
    }
  });
});

/**
 * Tests of methods of cryptographic key classes.
 */
describe("methods of cryptographic key classes", () => {
  test("generate, dump, JSONify, and load for the store operation", async () => {
    for (const [Key, cluster_] of [
      [blindfold.SecretKey, cluster(1)],
      [blindfold.SecretKey, cluster(3)],
      [blindfold.ClusterKey, cluster(3)],
    ] as [
      typeof blindfold.SecretKey | typeof blindfold.ClusterKey,
      blindfold.Cluster,
    ][]) {
      const key = await Key.generate(cluster_, {
        store: true,
      });

      const keyObject = JSON.parse(JSON.stringify(key.dump()));
      const keyLoaded = Key.load(keyObject);
      expect(keyLoaded).toBeInstanceOf(Key);
      expect(keyLoaded).toEqual(key);
    }
  });

  test("generate, dump, JSONify, and load for the match operation", async () => {
    for (const cluster_ of [cluster(1), cluster(3)]) {
      const secretKey = await blindfold.SecretKey.generate(cluster_, {
        match: true,
      });

      const secretKeyObject = JSON.parse(JSON.stringify(secretKey.dump()));
      const secretKeyLoaded = blindfold.SecretKey.load(secretKeyObject);
      expect(secretKeyLoaded).toBeInstanceOf(blindfold.SecretKey);
      expect(secretKeyLoaded).toEqual(secretKey);
    }
  });

  test("generate, dump, JSONify, and load for the sum operation with single node", async () => {
    const secretKey = secretKeyForSumWithOneNode;
    const publicKey = await blindfold.PublicKey.generate(secretKey);

    const secretKeyObject = JSON.parse(JSON.stringify(secretKey.dump()));
    const secretKeyLoaded = blindfold.SecretKey.load(secretKeyObject);
    expect(secretKeyLoaded).toBeInstanceOf(blindfold.SecretKey);
    expect(secretKeyLoaded).toEqual(secretKey);

    const publicKeyObject = JSON.parse(JSON.stringify(publicKey.dump()));
    const publicKeyLoaded = blindfold.PublicKey.load(
      publicKeyObject,
    ) as blindfold.PublicKey;
    expect(publicKeyLoaded).toBeInstanceOf(blindfold.PublicKey);
    expect(publicKeyLoaded).toEqual(publicKey);
  });

  test("generate, dump, JSONify, and load for the sum operation with multiple (without/with threshold) nodes", async () => {
    for (const [Key, cluster_, threshold] of [
      [blindfold.SecretKey, cluster(3), undefined],
      [blindfold.SecretKey, cluster(3), 2],
      [blindfold.SecretKey, cluster(3), 3],
      [blindfold.ClusterKey, cluster(3), undefined],
      [blindfold.ClusterKey, cluster(3), 2],
      [blindfold.ClusterKey, cluster(3), 3],
    ] as [
      typeof blindfold.SecretKey | typeof blindfold.ClusterKey,
      blindfold.Cluster,
      number,
    ][]) {
      const key = await Key.generate(cluster_, { sum: true }, threshold);
      const keyObject = JSON.parse(JSON.stringify(key.dump()));
      const keyLoaded = Key.load(keyObject);
      expect(keyLoaded).toBeInstanceOf(Key);
      expect(keyLoaded).toEqual(key);
    }
  });

  test("key generation from seed for the store operation with single and multiple nodes", async () => {
    for (const cluster_ of [cluster(1), cluster(3)]) {
      for (const seed of seedValues) {
        const secretKeyFromSeed = await blindfold.SecretKey.generate(
          cluster_,
          { store: true },
          undefined,
          seed,
        );
        expect(
          await toHashBase64(secretKeyFromSeed.material as Uint8Array),
        ).toStrictEqual("2bW6BLeeCTqsCqrijSkBBPGjDb/gzjtGnFZt0nsZP8w=");
      }

      const secretKey = await blindfold.SecretKey.generate(cluster_, {
        store: true,
      });
      expect(await toHashBase64(secretKey.material as Uint8Array)).not.toEqual(
        "2bW6BLeeCTqsCqrijSkBBPGjDb/gzjtGnFZt0nsZP8w=",
      );
    }
  });

  test("key generation from seed for the match operation with single and multiple nodes", async () => {
    for (const cluster_ of [cluster(1), cluster(3)]) {
      for (const seed of seedValues) {
        const secretKeyFromSeed = await blindfold.SecretKey.generate(
          cluster_,
          { match: true },
          undefined,
          seed,
        );
        expect(
          await toHashBase64(secretKeyFromSeed.material as Uint8Array),
        ).toStrictEqual("qbcFGTOGTPo+vs3EChnVUWk5lnn6L6Cr/DIq8li4H+4=");
      }

      const secretKey = await blindfold.SecretKey.generate(cluster_, {
        match: true,
      });
      expect(await toHashBase64(secretKey.material as Uint8Array)).not.toEqual(
        "qbcFGTOGTPo+vs3EChnVUWk5lnn6L6Cr/DIq8li4H+4=",
      );
    }
  });

  test("key generation from seed for the sum operation with multiple (without/with threshold) nodes", async () => {
    for (const [n, hashFromMaterial] of [
      [2, "GmmTqmaeT0Uhe1h94yJHEQXG45beO6t+z/m9EBZCNAY="],
      [3, "L8RiHNq2EUgt/fDOoUw9QK2NISeUkAkhxHHIPoHPZ84="],
      [4, "xUiGGrAEfTZpNl2aIe2V+Vk+HCSTElREbeXNV/hePJg="],
      [5, "4k7lscMoSb8WOcIcChURfE6GfIe5gN+Hc3MiQeD4tKI="],
    ] as [number, string][]) {
      for (const threshold of ([undefined] as (undefined | number)[]).concat(
        new Array(n).fill(0).map((_, i) => i + 1),
      )) {
        for (const seed of seedValues) {
          const secretKeyFromSeed = await blindfold.SecretKey.generate(
            cluster(n),
            { sum: true },
            threshold,
            seed,
          );
          expect(
            await toHashBase64(secretKeyFromSeed.material as number[]),
          ).toStrictEqual(hashFromMaterial);
        }

        const secretKey = await blindfold.SecretKey.generate(
          cluster(n),
          { sum: true },
          threshold,
        );
        expect(await toHashBase64(secretKey.material as number[])).not.toEqual(
          hashFromMaterial,
        );
      }
    }
  });
});

/**
 * Tests of errors thrown by methods of cryptographic key classes.
 */
describe("errors thrown by methods of cryptographic key classes", () => {
  test("errors that can occur during key generation", async () => {
    // Cluster configuration errors.
    for (const Key of [blindfold.SecretKey, blindfold.ClusterKey]) {
      for (const ops of [{ store: true }, { match: true }, { sum: true }]) {
        try {
          await Key.generate("abc" as unknown as { nodes: object[] }, ops);
          expectThrow();
        } catch (e) {
          expect(e).toStrictEqual(
            TypeError("cluster configuration must be a simple object"),
          );
        }

        try {
          await Key.generate({} as unknown as { nodes: object[] }, ops);
          expectThrow();
        } catch (e) {
          expect(e).toStrictEqual(
            Error("cluster configuration must specify nodes"),
          );
        }

        try {
          await Key.generate(
            { nodes: 123 } as unknown as { nodes: object[] },
            ops,
          );
          expectThrow();
        } catch (e) {
          expect(e).toStrictEqual(
            Error("cluster configuration nodes specification must be an array"),
          );
        }

        try {
          await Key.generate(cluster(0), ops);
          expectThrow();
        } catch (e) {
          expect(e).toStrictEqual(
            Error("cluster configuration must contain at least one node"),
          );
        }

        if (Key === blindfold.ClusterKey && !ops.match) {
          try {
            await Key.generate(cluster(1), ops);
            expectThrow();
          } catch (e) {
            expect(e).toStrictEqual(
              Error("cluster configuration must contain at least two nodes"),
            );
          }
        }
      }
    }

    // Operations specification errors.
    for (const Key of [blindfold.SecretKey, blindfold.ClusterKey]) {
      for (const n of [1, 2, 3, 4]) {
        if (!(Key === blindfold.ClusterKey && n === 1)) {
          try {
            await Key.generate(
              cluster(n),
              "123" as unknown as { sum: boolean },
            );
            expectThrow();
          } catch (e) {
            expect(e).toStrictEqual(
              TypeError("operations specification must be a simple object"),
            );
          }

          try {
            await Key.generate(cluster(n), { foo: true } as unknown as {
              sum: boolean;
            });
            expectThrow();
          } catch (e) {
            expect(e).toStrictEqual(
              Error(
                "permitted operations are limited to store, match, and sum",
              ),
            );
          }

          try {
            await Key.generate(cluster(n), { store: 123 } as unknown as {
              sum: boolean;
            });
            expectThrow();
          } catch (e) {
            expect(e).toStrictEqual(
              TypeError("operations specification values must be boolean"),
            );
          }

          try {
            await Key.generate(cluster(n), {});
            expectThrow();
          } catch (e) {
            expect(e).toStrictEqual(
              Error(
                "operations specification must enable exactly one operation",
              ),
            );
          }
        }

        if (Key === blindfold.ClusterKey && n >= 2) {
          try {
            await blindfold.ClusterKey.generate(cluster(n), { match: true });
            expectThrow();
          } catch (e) {
            expect(e).toStrictEqual(
              Error(
                "cluster keys cannot support matching-compatible encryption",
              ),
            );
          }
        }
      }
    }

    // Threshold errors.
    for (const Key of [blindfold.SecretKey, blindfold.ClusterKey]) {
      for (const n of [1, 2, 3, 4]) {
        if (!(Key === blindfold.ClusterKey && n === 1)) {
          try {
            await Key.generate(
              cluster(n),
              { sum: true },
              "abc" as unknown as number,
            );
            expectThrow();
          } catch (e) {
            expect(e).toStrictEqual(TypeError("threshold must be a number"));
          }

          try {
            await Key.generate(cluster(n), { sum: true }, 0.123);
            expectThrow();
          } catch (e) {
            expect(e).toStrictEqual(
              Error("threshold must be an integer number"),
            );
          }

          if (n === 1) {
            try {
              await Key.generate(cluster(n), { sum: true }, 1);
              expectThrow();
            } catch (e) {
              expect(e).toStrictEqual(
                Error(
                  "thresholds are only supported for multiple-node clusters",
                ),
              );
            }
          }

          if (n >= 2) {
            for (const t of [2 - n, n + 1]) {
              try {
                await Key.generate(cluster(n), { sum: true }, t);
                expectThrow();
              } catch (e) {
                expect(e).toStrictEqual(
                  Error(
                    "threshold must be a positive integer not larger than the cluster size",
                  ),
                );
              }
            }

            try {
              await Key.generate(cluster(n), { store: true }, n);
              expectThrow();
            } catch (e) {
              expect(e).toStrictEqual(
                Error("thresholds are only supported for the sum operation"),
              );
            }
          }
        }
      }
    }

    // Seed errors.
    for (const n of [1, 2, 3, 4]) {
      for (const ops of [{ store: true }, { match: true }, { sum: true }]) {
        try {
          await blindfold.SecretKey.generate(
            cluster(n),
            ops,
            undefined,
            123 as unknown as string,
          );
          expectThrow();
        } catch (e) {
          expect(e).toStrictEqual(
            TypeError("seed must be string, Uint8Array, or Buffer"),
          );
        }

        if (n === 1 && ops.sum) {
          try {
            await blindfold.SecretKey.generate(
              cluster(n),
              ops,
              undefined,
              "ABC",
            );
            expectThrow();
          } catch (e) {
            expect(e).toStrictEqual(
              Error(
                "seed-based derivation of summation-compatible secret keys " +
                  "is not supported for single-node clusters",
              ),
            );
          }
        }
      }
    }

    // Public key errors.
    for (const Key of [blindfold.SecretKey, blindfold.ClusterKey]) {
      for (const n of [1, 2, 3, 4]) {
        for (const ops of [{ store: true }, { match: true }, { sum: true }]) {
          if (!(Key === blindfold.ClusterKey && (n === 1 || ops.match))) {
            if (Key === blindfold.ClusterKey) {
              try {
                const key = await Key.generate(cluster(n), ops);
                await blindfold.PublicKey.generate(key as blindfold.SecretKey);
                expectThrow();
              } catch (e) {
                expect(e).toStrictEqual(TypeError("secret key expected"));
              }
            }

            // Valid but incompatible secret keys.
            if (Key === blindfold.SecretKey && !(n === 1 && ops.sum)) {
              try {
                const key = await Key.generate(cluster(n), ops);
                await blindfold.PublicKey.generate(key as blindfold.SecretKey);
                expectThrow();
              } catch (e) {
                expect(e).toStrictEqual(
                  Error("secret key must contain public key"),
                );
              }
            }

            // Potentially compatible but malformed secret keys.
            if (Key === blindfold.SecretKey && n === 1 && ops.sum) {
              try {
                const key = await Key.generate(cluster(n), ops);
                (key as unknown as { material: number }).material = 123;
                await blindfold.PublicKey.generate(key as blindfold.SecretKey);
                expectThrow();
              } catch (e) {
                expect(e).toStrictEqual(
                  TypeError("secret key material must be an object"),
                );
              }

              try {
                const key = await Key.generate(cluster(n), ops);
                (key as unknown as { material: object }).material = {};
                await blindfold.PublicKey.generate(key as blindfold.SecretKey);
                expectThrow();
              } catch (e) {
                expect(e).toStrictEqual(
                  Error("secret key must contain public key"),
                );
              }

              try {
                const key = await Key.generate(cluster(n), ops);
                (
                  key as unknown as { material: { publicKey: number } }
                ).material.publicKey = 123;
                await blindfold.PublicKey.generate(key as blindfold.SecretKey);
                expectThrow();
              } catch (e) {
                expect(e).toStrictEqual(
                  TypeError(
                    "secret key must contain public key of the correct type",
                  ),
                );
              }
            }
          }
        }
      }
    }
  });

  test("errors that can occur during key dumping and loading", async () => {
    // Errors that can occur due to checks performed within key generation
    // are not considered within these tests. The only exception is that a
    // single test is included to ensure that the corresponding constructors
    // or validation methods are invoked. These are identified via comments.

    // Secret keys.
    type secretKeyObjectType = {
      cluster: blindfold.Cluster;
      operations: blindfold.Operations;
      material:
        | string
        | { n: string; g: string; l: string; m: string }
        | number[];
    };

    // Secret keys: invalid cluster configuration, invalid operations
    // specification, or material incompatible with these.
    for (const n of [1, 2, 3, 4]) {
      for (const ops of [{ store: true }, { match: true }, { sum: true }]) {
        // Check that cluster configuration validation is invoked.
        try {
          const secKey = await blindfold.SecretKey.generate(cluster(n), ops);
          const secKeyObject = secKey.dump();
          delete secKeyObject["cluster" as keyof typeof secKeyObject];
          blindfold.SecretKey.load(secKeyObject as secretKeyObjectType);
          expectThrow();
        } catch (e) {
          expect(e).toStrictEqual(
            TypeError("cluster configuration must be a simple object"),
          );
        }

        // Check that operation specification validation is invoked.
        try {
          const secKey = await blindfold.SecretKey.generate(cluster(n), ops);
          const secKeyObject = secKey.dump() as { operations?: object };
          delete secKeyObject["operations" as keyof typeof secKeyObject];
          blindfold.SecretKey.load(secKeyObject as secretKeyObjectType);
          expectThrow();
        } catch (e) {
          expect(e).toStrictEqual(
            TypeError("operations specification must be a simple object"),
          );
        }

        // Check that key attribute compatibility validation is invoked.
        try {
          const secKey = await blindfold.SecretKey.generate(cluster(n), ops);
          const secKeyObject = secKey.dump();
          (secKeyObject as unknown as { threshold: number }).threshold =
            "abc" as unknown as number;
          blindfold.SecretKey.load(secKeyObject as secretKeyObjectType);
          expectThrow();
        } catch (e) {
          expect(e).toStrictEqual(TypeError("threshold must be a number"));
        }

        // Check all material attribute type errors for the possible operations.
        try {
          const secKey = await blindfold.SecretKey.generate(cluster(n), ops);
          const secKeyObject = secKey.dump();
          delete secKeyObject["material" as keyof typeof secKeyObject];
          blindfold.SecretKey.load(secKeyObject as secretKeyObjectType);
          expectThrow();
        } catch (e) {
          expect(e).toStrictEqual(
            TypeError(
              "operations specification requires key material to be " +
                (ops.sum
                  ? n === 1
                    ? "a simple object"
                    : "an array"
                  : "a string"),
            ),
          );
        }
      }
    }

    // Secret keys: invalid material for matching and storage.
    for (const n of [1, 2, 3, 4]) {
      const secKeyForStore = await blindfold.SecretKey.generate(cluster(n), {
        store: true,
      });
      const secKeyForMatch = await blindfold.SecretKey.generate(cluster(n), {
        match: true,
      });

      try {
        const secKeyForStoreObject = secKeyForStore.dump();
        const secKeyForMatchObject = secKeyForMatch.dump();
        secKeyForStoreObject.material = secKeyForMatchObject.material;
        blindfold.SecretKey.load(secKeyForStoreObject);
        expectThrow();
      } catch (e) {
        expect(e).toStrictEqual(
          Error("key material must have a length of 32 bytes"),
        );
      }

      try {
        const secKeyForStoreObject = secKeyForStore.dump();
        const secKeyForMatchObject = secKeyForMatch.dump();
        secKeyForMatchObject.material = secKeyForStoreObject.material;
        blindfold.SecretKey.load(secKeyForMatchObject);
        expectThrow();
      } catch (e) {
        expect(e).toStrictEqual(
          Error("key material must have a length of 64 bytes"),
        );
      }
    }

    // Secret keys: invalid material for summation on single-node clusters.
    for (const param of ["l", "m", "n", "g"]) {
      type materialType = { l: string; m: string; n: string; g: string };
      const secKey = secretKeyForSumWithOneNode;

      try {
        const secKeyObject = secKey.dump();
        if (secKeyObject.material !== undefined) {
          const material = secKeyObject.material as unknown as materialType;
          delete material[param as keyof typeof material];
        }
        blindfold.SecretKey.load(secKeyObject);
        expectThrow();
      } catch (e) {
        expect(e).toStrictEqual(
          Error("key material must contain all required parameters"),
        );
      }

      try {
        const secKeyObject = secKey.dump();
        const material = secKeyObject.material as unknown as materialType;
        material[param as keyof typeof material] = 123 as unknown as string;
        blindfold.SecretKey.load(secKeyObject);
        expectThrow();
      } catch (e) {
        expect(e).toStrictEqual(
          TypeError("key material parameter values must be strings"),
        );
      }

      try {
        const secKeyObject = secKey.dump();
        const material = secKeyObject.material as unknown as materialType;
        material[param as keyof typeof material] = "abc";
        blindfold.SecretKey.load(secKeyObject);
        expectThrow();
      } catch (e) {
        expect(e).toStrictEqual(
          Error(
            "key material parameter strings must be convertible to integer values",
          ),
        );
      }
    }

    // Secret keys: invalid material for summation on multiple-node clusters.
    for (const n of [2, 3, 4]) {
      const secKey = await blindfold.SecretKey.generate(cluster(n), {
        sum: true,
      });

      try {
        const secKeyObject = secKey.dump();
        secKeyObject.material = "abc" as unknown as number[];
        blindfold.SecretKey.load(secKeyObject);
        expectThrow();
      } catch (e) {
        expect(e).toStrictEqual(
          TypeError(
            "operations specification requires key material to be an array",
          ),
        );
      }

      try {
        const secKeyObject = secKey.dump();
        const material = secKeyObject.material as number[];
        material.pop();
        blindfold.SecretKey.load(secKeyObject);
        expectThrow();
      } catch (e) {
        expect(e).toStrictEqual(
          Error(
            `cluster configuration requires key material to have length ${n}`,
          ),
        );
      }

      try {
        const secKeyObject = secKey.dump();
        const material = secKeyObject.material as number[];
        material[0] = "abc" as unknown as number;
        blindfold.SecretKey.load(secKeyObject);
        expectThrow();
      } catch (e) {
        expect(e).toStrictEqual(TypeError("key material must contain numbers"));
      }

      try {
        const secKeyObject = secKey.dump();
        const material = secKeyObject.material as number[];
        material[0] = 1.23;
        blindfold.SecretKey.load(secKeyObject);
        expectThrow();
      } catch (e) {
        expect(e).toStrictEqual(
          Error("key material must contain integer numbers"),
        );
      }

      try {
        const secKeyObject = secKey.dump();
        const material = secKeyObject.material as number[];
        material[0] = 0; // Masks for secret shares must be nonzero.
        blindfold.SecretKey.load(secKeyObject);
        expectThrow();
      } catch (e) {
        expect(e).toStrictEqual(
          Error(
            "key material must contain integer numbers within the correct range",
          ),
        );
      }
    }

    // Cluster keys.
    type clusterKeyObjectType = {
      cluster: blindfold.Cluster;
      operations: blindfold.Operations;
    };

    for (const n of [1, 2, 3, 4]) {
      for (const ops of [{ store: true }, { match: true }, { sum: true }]) {
        if (n !== 1 && !ops.match) {
          // Check that cluster configuration validation is invoked.
          try {
            const cluKey = await blindfold.ClusterKey.generate(cluster(n), ops);
            let cluKeyObject = cluKey.dump();
            cluKeyObject = {} as unknown as clusterKeyObjectType;
            blindfold.ClusterKey.load(
              cluKeyObject as {
                cluster: blindfold.Cluster;
                operations: blindfold.Operations;
              },
            );
            expectThrow();
          } catch (e) {
            expect(e).toStrictEqual(
              TypeError("cluster configuration must be a simple object"),
            );
          }
        }

        if (n === 1 && !ops.match) {
          try {
            const cluKey = await blindfold.ClusterKey.generate(cluster(2), ops);
            const cluKeyObject = cluKey.dump();
            cluKeyObject.cluster = cluster(n);
            blindfold.ClusterKey.load(cluKeyObject);
            expectThrow();
          } catch (e) {
            expect(e).toStrictEqual(
              Error("cluster configuration must contain at least two nodes"),
            );
          }
        }

        if (n !== 1 && !ops.match) {
          // Check that operations specification validation is invoked.
          try {
            const cluKey = await blindfold.ClusterKey.generate(cluster(n), ops);
            const cluKeyObject = cluKey.dump() as { operations?: object };
            delete cluKeyObject["operations" as keyof typeof cluKeyObject];
            blindfold.ClusterKey.load(cluKeyObject as clusterKeyObjectType);
            expectThrow();
          } catch (e) {
            expect(e).toStrictEqual(
              TypeError("operations specification must be a simple object"),
            );
          }
        }

        if (n !== 1 && ops.match) {
          try {
            const cluKey = await blindfold.ClusterKey.generate(cluster(n), {
              store: true,
            });
            const cluKeyObject = cluKey.dump();
            cluKeyObject.operations = ops;
            blindfold.ClusterKey.load(cluKeyObject);
            expectThrow();
          } catch (e) {
            expect(e).toStrictEqual(
              Error(
                "cluster keys cannot support matching-compatible encryption",
              ),
            );
          }
        }

        if (n !== 1 && !ops.match) {
          // Check that key attribute compatibility validation is invoked.
          try {
            const cluKey = await blindfold.ClusterKey.generate(cluster(n), ops);
            const cluKeyObject = cluKey.dump() as unknown as {
              threshold: number;
            };
            cluKeyObject.threshold = "abc" as unknown as number;
            blindfold.ClusterKey.load(
              cluKeyObject as unknown as clusterKeyObjectType,
            );
            expectThrow();
          } catch (e) {
            expect(e).toStrictEqual(TypeError("threshold must be a number"));
          }

          try {
            const cluKey = await blindfold.ClusterKey.generate(cluster(n), ops);
            const cluKeyObject = cluKey.dump() as unknown as {
              material: object;
            };
            cluKeyObject.material = {};
            blindfold.ClusterKey.load(
              cluKeyObject as unknown as clusterKeyObjectType,
            );
            expectThrow();
          } catch (e) {
            expect(e).toStrictEqual(
              Error("cluster keys cannot contain key material"),
            );
          }
        }
      }
    }

    // Public keys.
    type publicKeyObjectType = {
      cluster: blindfold.Cluster;
      operations: blindfold.Operations;
      material: { n: string; g: string };
    };

    // Check that cluster configuration validation is invoked.
    const secKey = secretKeyForSumWithOneNode;
    const pubKey = await blindfold.PublicKey.generate(secKey);

    try {
      const pubKeyObject = pubKey.dump();
      delete pubKeyObject["cluster" as keyof typeof pubKeyObject];
      blindfold.PublicKey.load(pubKeyObject);
      expectThrow();
    } catch (e) {
      expect(e).toStrictEqual(
        TypeError("cluster configuration must be a simple object"),
      );
    }

    // Check that operations specification validation is invoked.
    try {
      const pubKeyObject = pubKey.dump();
      delete pubKeyObject["operations" as keyof typeof pubKeyObject];
      blindfold.PublicKey.load(pubKeyObject);
      expectThrow();
    } catch (e) {
      expect(e).toStrictEqual(
        TypeError("operations specification must be a simple object"),
      );
    }

    try {
      const pubKeyObject = pubKey.dump();
      pubKeyObject.cluster = cluster(2);
      blindfold.PublicKey.load(pubKeyObject);
      expectThrow();
    } catch (e) {
      expect(e).toStrictEqual(
        Error("public keys are only supported for single-node clusters"),
      );
    }

    for (const ops of [{ store: true }, { match: true }]) {
      try {
        const pubKeyObject = pubKey.dump();
        pubKeyObject.operations = ops;
        blindfold.PublicKey.load(pubKeyObject);
        expectThrow();
      } catch (e) {
        expect(e).toStrictEqual(
          Error("public keys can only support the sum operation"),
        );
      }
    }

    try {
      const pubKeyObject = pubKey.dump() as unknown as { threshold: number };
      pubKeyObject.threshold = 2;
      blindfold.PublicKey.load(pubKeyObject as unknown as publicKeyObjectType);
      expectThrow();
    } catch (e) {
      expect(e).toStrictEqual(Error("public keys cannot specify a threshold"));
    }

    try {
      const pubKeyObject = pubKey.dump();
      delete pubKeyObject["material" as keyof typeof pubKeyObject];
      blindfold.PublicKey.load(pubKeyObject);
      expectThrow();
    } catch (e) {
      expect(e).toStrictEqual(
        TypeError("key material must be a simple object"),
      );
    }

    for (const param of ["n", "g"]) {
      try {
        const pubKeyObject = pubKey.dump();
        const material = pubKeyObject.material;
        delete material[param as keyof typeof material];
        blindfold.PublicKey.load(pubKeyObject);
        expectThrow();
      } catch (e) {
        expect(e).toStrictEqual(
          Error("key material must contain all required parameters"),
        );
      }

      try {
        const pubKeyObject = pubKey.dump();
        const material = pubKeyObject.material;
        material[param as keyof typeof material] = 123 as unknown as string;
        blindfold.PublicKey.load(pubKeyObject);
        expectThrow();
      } catch (e) {
        expect(e).toStrictEqual(
          TypeError("key material parameter values must be strings"),
        );
      }

      try {
        const pubKeyObject = pubKey.dump();
        const material = pubKeyObject.material;
        material[param as keyof typeof material] = "abc";
        blindfold.PublicKey.load(pubKeyObject);
        expectThrow();
      } catch (e) {
        expect(e).toStrictEqual(
          Error(
            "key material parameter strings must be convertible to integer values",
          ),
        );
      }
    }
  });
});

/**
 * Tests of the functional and algebraic properties of encryption/decryption functions.
 */
describe("encryption and decryption functions", () => {
  test("encryption and decryption for the store operation with single and multiple nodes", async () => {
    for (const cluster_ of [cluster(1), cluster(2), cluster(3)]) {
      for (const Key of [blindfold.SecretKey, blindfold.ClusterKey]) {
        if (cluster_.nodes.length === 1 && Key === blindfold.ClusterKey) {
          continue;
        }

        const key = await Key.generate(cluster_, { store: true });
        // biome-ignore format: Concise list of test case parameter values.
        for (const plaintext of (
          plaintextIntegerValues.concat([
            "", "abc", "X".repeat(_PLAINTEXT_STRING_BUFFER_LEN_MAX),
            new Uint8Array([]), new Uint8Array([1, 2, 3]), new Uint8Array([4, 5, 6, 7, 8, 9]),
          ])
        )) {
          const ciphertext = await blindfold.encrypt(key, plaintext);
          const decrypted = await blindfold.decrypt(key, ciphertext);
          expect(decrypted).toEqual(
            typeof plaintext === "number" ? BigInt(plaintext) : plaintext,
          );
        }
      }
    }
  });

  test("encryption for the match operation", async () => {
    for (const cluster_ of [cluster(1), cluster(3)]) {
      const secretKeyA = await blindfold.SecretKey.generate(cluster_, {
        match: true,
      });
      const secretKeyB = await blindfold.SecretKey.generate(cluster_, {
        match: true,
      });

      for (const [plaintextOne, plaintextTwo, comparison] of [
        [123, 123, true],
        [123n, 123n, true],
        [123, 0, false],
        [123, 123n, true],
        ["ABC", "ABC", true],
        ["ABC", "abc", false],
        [new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 3]), true],
        [new Uint8Array([1, 2, 3]), new Uint8Array([4, 5, 6, 7, 8, 9]), false],
      ] as [
        number | bigint | string | Uint8Array,
        number | bigint | string | Uint8Array,
        boolean,
      ][]) {
        const ciphertextOneA = await blindfold.encrypt(
          secretKeyA,
          plaintextOne,
        );
        const ciphertextTwoA = await blindfold.encrypt(
          secretKeyA,
          plaintextTwo,
        );
        expect(
          JSON.stringify(ciphertextOneA) === JSON.stringify(ciphertextTwoA),
        ).toEqual(comparison);

        const ciphertextOneB = await blindfold.encrypt(
          secretKeyB,
          plaintextOne,
        );
        expect(
          JSON.stringify(ciphertextOneA) === JSON.stringify(ciphertextOneB),
        ).toEqual(false);
      }
    }
  });

  test("encryption and decryption for sum operation with single node", async () => {
    const secretKey = secretKeyForSumWithOneNode;
    const publicKey = await blindfold.PublicKey.generate(secretKey);
    for (const plaintext of plaintextIntegerValues) {
      const ciphertext = await blindfold.encrypt(publicKey, plaintext);
      const decrypted = await blindfold.decrypt(secretKey, ciphertext);
      expect(decrypted).toEqual(
        typeof plaintext === "number" ? BigInt(plaintext) : plaintext,
      );
    }
  });

  test("encryption and decryption for the sum operation with single and multiple (without/with threshold) nodes", async () => {
    // biome-ignore format: Concise list of test case parameter values.
    for (const [cluster_, threshold, combinations] of [
      [cluster(1), undefined, [[0]]],
      [cluster(3), undefined, [[0, 1, 2]]],

      // Scenarios with thresholds but no missing shares.
      [cluster(3), 1, [[0, 1, 2]]],
      [cluster(3), 2, [[0, 1, 2]]],
      [cluster(3), 3, [[0, 1, 2]]],

      // Scenarios with thresholds and missing shares.
      [cluster(3), 2, [[0, 1], [0, 2], [1, 2]]],
      [cluster(4), 2, [[0, 1], [1, 2], [2, 3], [0, 2], [1, 3], [0, 3], [0, 1, 2]]],
      [cluster(4), 3, [[0, 1, 2], [1, 2, 3], [0, 1, 3], [0, 2, 3]]],
      [cluster(5), 2, [[0, 4], [1, 3], [0, 2], [2, 3]]],
      [cluster(5), 3, [[0, 1, 4], [1, 3, 4], [0, 2, 4], [1, 2, 3], [1, 2, 3, 4]]],
      [cluster(5), 4, [[0, 1, 4, 2], [0, 1, 3, 4]]],
    ] as [blindfold.Cluster, number, number[][]][]) {
      for (const Key of [blindfold.SecretKey, blindfold.ClusterKey]) {
        if (cluster_.nodes.length === 1 && Key === blindfold.ClusterKey) {
          continue;
        }

        const key = await Key.generate(cluster_, { sum: true }, threshold);
        for (const plaintext of plaintextIntegerValues) {
          const ciphertext = await blindfold.encrypt(key, plaintext);
          for (const combination of combinations) {
            const decrypted = await blindfold.decrypt(
              key,
              threshold === undefined
                ? ciphertext
                : (combination.map((i) => ciphertext[i]) as number[]),
            );
            expect(decrypted).toEqual(
              typeof plaintext === "number" ? BigInt(plaintext) : plaintext,
            );
          }
        }
      }
    }
  });
});

/**
 * Tests of the portable representation of ciphertexts.
 */
describe("portable representation of ciphertexts", () => {
  test("secret share representation for store operation with multiple nodes", async () => {
    const clusterKey = await blindfold.ClusterKey.generate(cluster(3), {
      store: true,
    });
    const plaintext = "abc";
    const ciphertext = ["Ifkz2Q==", "8nqHOQ==", "0uLWgw=="];
    const decrypted = await blindfold.decrypt(clusterKey, ciphertext);
    expect(decrypted).toEqual(plaintext);
  });

  test("secret share representation for sum operation with multiple nodes", async () => {
    const clusterKey = await blindfold.ClusterKey.generate(cluster(3), {
      sum: true,
    });
    const plaintext = BigInt(123);
    const ciphertext = [456, 246, 4294967296 + 15 - 123 - 456];
    const decrypted = await blindfold.decrypt(clusterKey, ciphertext);
    expect(decrypted).toEqual(plaintext);
  });

  test("secret share representation for sum operation with multiple nodes and threshold", async () => {
    const clusterKey = await blindfold.ClusterKey.generate(
      cluster(3),
      { sum: true },
      3,
    );
    const plaintext = BigInt(123);
    const ciphertext = [
      [1, 1382717699],
      [2, 2765435275],
      [3, 4148152851],
    ];
    const decrypted = await blindfold.decrypt(clusterKey, ciphertext);
    expect(decrypted).toEqual(plaintext);
  });
});

/**
 * Tests verifying that encryption/decryption methods return expected errors.
 */
describe("errors involving encryption and decryption functions", () => {
  test("errors that can occur during encryption", async () => {
    try {
      const secKey = await blindfold.SecretKey.generate(cluster(1), {
        store: true,
      });
      secKey.operations = {};
      await blindfold.encrypt(secKey, 123);
      expectThrow();
    } catch (e) {
      expect(e).toStrictEqual(
        Error("cannot encrypt the supplied plaintext using the supplied key"),
      );
    }

    try {
      const secKey = await blindfold.SecretKey.generate(cluster(1), {
        store: true,
      });
      secKey.material = new Uint8Array();
      await blindfold.encrypt(secKey, 123);
      expectThrow();
    } catch (e) {
      expect(e).toStrictEqual(
        Error("cannot encrypt the supplied plaintext using the supplied key"),
      );
    }

    for (const ops of [{ store: true }, { match: true }]) {
      const secKey = await blindfold.SecretKey.generate(cluster(1), ops);

      try {
        await blindfold.encrypt(
          secKey,
          Number(_PLAINTEXT_SIGNED_INTEGER_MAX) + 1,
        );
        expectThrow();
      } catch (e) {
        expect(e).toStrictEqual(
          Error("numeric plaintext must be a valid 32-bit signed integer"),
        );
      }

      try {
        await blindfold.encrypt(
          secKey,
          "x".repeat(_PLAINTEXT_STRING_BUFFER_LEN_MAX + 1),
        );
        expectThrow();
      } catch (e) {
        expect(e).toStrictEqual(
          Error(
            "string or binary plaintext must be at most " +
              `${_PLAINTEXT_STRING_BUFFER_LEN_MAX} bytes or fewer in length`,
          ),
        );
      }
    }

    for (const n of [1, 3]) {
      const secKey =
        n === 1
          ? secretKeyForSumWithOneNode
          : await blindfold.SecretKey.generate(cluster(n), { sum: true });
      const encKey =
        n === 1 ? await blindfold.PublicKey.generate(secKey) : secKey;

      try {
        await blindfold.encrypt(encKey, "abc");
        expectThrow();
      } catch (e) {
        expect(e).toStrictEqual(
          TypeError(
            "summation-compatible encryption requires a numeric plaintext",
          ),
        );
      }

      try {
        await blindfold.encrypt(encKey, _PLAINTEXT_SIGNED_INTEGER_MAX + 1n);
        expectThrow();
      } catch (e) {
        expect(e).toStrictEqual(
          Error("numeric plaintext must be a valid 32-bit signed integer"),
        );
      }
    }
  });

  test("errors that can occur during decryption with an invalid key", async () => {
    try {
      const secKey = await blindfold.SecretKey.generate(cluster(1), {
        store: true,
      });
      const cipher = await blindfold.encrypt(secKey, 123);
      secKey.operations = {};
      await blindfold.decrypt(secKey, cipher);
      expectThrow();
    } catch (e) {
      expect(e).toStrictEqual(
        Error("cannot decrypt the supplied ciphertext using the supplied key"),
      );
    }

    try {
      const cluKey = await blindfold.ClusterKey.generate(
        cluster(3),
        { sum: true },
        2,
      );
      cluKey.threshold = 4; // Invalid key manipulation.
      await blindfold.encrypt(cluKey, 123);
      expectThrow();
    } catch (e) {
      expect(e).toStrictEqual(
        Error(
          "quantity of shares cannot be less than the reconstruction threshold",
        ),
      );
    }
  });

  test("errors that can occur during decryption when the key and ciphertext conflict", async () => {
    for (const ops of [{ store: true }, { match: true }]) {
      const secKeyOne = await blindfold.SecretKey.generate(cluster(1), ops);
      const secKeyTwo = await blindfold.SecretKey.generate(cluster(2), ops);
      const secKeyThree = await blindfold.SecretKey.generate(cluster(3), ops);
      const cipherOne = await blindfold.encrypt(secKeyOne, 123);
      const cipherTwo = await blindfold.encrypt(secKeyTwo, 123);

      try {
        await blindfold.decrypt(secKeyOne, cipherTwo);
        expectThrow();
      } catch (e) {
        expect(e).toStrictEqual(
          Error("key requires a valid ciphertext from a single-node cluster"),
        );
      }

      try {
        await blindfold.decrypt(secKeyTwo, cipherOne);
        expectThrow();
      } catch (e) {
        expect(e).toStrictEqual(
          Error("key requires a valid ciphertext from a multiple-node cluster"),
        );
      }

      try {
        await blindfold.decrypt(secKeyThree, cipherTwo);
        expectThrow();
      } catch (e) {
        expect(e).toStrictEqual(
          Error(
            "ciphertext must have enough shares for cluster size or threshold",
          ),
        );
      }
    }

    for (const n of [1, 3]) {
      try {
        const secKey = await blindfold.SecretKey.generate(cluster(n), {
          store: true,
        });
        const secKeyAlt = await blindfold.SecretKey.generate(cluster(n), {
          store: true,
        });
        const cipher = await blindfold.encrypt(secKey, 123);
        await blindfold.decrypt(secKeyAlt, cipher);
        expectThrow();
      } catch (e) {
        expect(e).toStrictEqual(
          Error(
            "cannot decrypt the supplied ciphertext using the supplied key",
          ),
        );
      }
    }
  });

  test("errors that can occur during decryption when the ciphertext is invalid", async () => {
    try {
      const secKey = await blindfold.SecretKey.generate(cluster(2), {
        store: true,
      });
      const cipher = (await blindfold.encrypt(secKey, "abc")) as number[];
      await blindfold.decrypt(secKey, [123, cipher[1]]);
      expectThrow();
    } catch (e) {
      expect(e).toStrictEqual(
        TypeError("secret shares must all be Base64-encoded binary values"),
      );
    }

    try {
      const secKey = await blindfold.SecretKey.generate(cluster(2), {
        store: true,
      });
      const cipherOne = (await blindfold.encrypt(secKey, "")) as string[];
      const cipherTwo = (await blindfold.encrypt(secKey, "abc")) as string[];
      await blindfold.decrypt(secKey, [cipherOne[0], cipherTwo[1]]);
      expectThrow();
    } catch (e) {
      expect(e).toStrictEqual(
        Error("secret shares must have matching lengths"),
      );
    }

    try {
      const secKey = await blindfold.SecretKey.generate(cluster(2), {
        sum: true,
      });
      const cipher = (await blindfold.encrypt(secKey, 123)) as string[];
      await blindfold.decrypt(secKey, ["abc", cipher[1]]);
      expectThrow();
    } catch (e) {
      expect(e).toStrictEqual(TypeError("secret shares must all be integers"));
    }

    try {
      const secKey = await blindfold.SecretKey.generate(cluster(2), {
        sum: true,
      });
      const cipher = (await blindfold.encrypt(secKey, 123)) as number[];
      await blindfold.decrypt(secKey, [-1, cipher[1]]);
      expectThrow();
    } catch (e) {
      expect(e).toStrictEqual(
        Error(
          "secret shares must all be nonnegative integers less than the modulus",
        ),
      );
    }

    try {
      const secKey = await blindfold.SecretKey.generate(
        cluster(3),
        { sum: true },
        2,
      );
      await blindfold.decrypt(secKey, [123, 456]);
      expectThrow();
    } catch (e) {
      expect(e).toStrictEqual(TypeError("secret shares must all be arrays"));
    }

    try {
      const secKey = await blindfold.SecretKey.generate(
        cluster(3),
        { sum: true },
        2,
      );
      const cipher = (await blindfold.encrypt(secKey, 123)) as number[][];
      await blindfold.decrypt(secKey, [cipher[0].slice(1), cipher[1]]);
      expectThrow();
    } catch (e) {
      expect(e).toStrictEqual(
        Error("secret shares must all have two components"),
      );
    }

    try {
      const secKey = await blindfold.SecretKey.generate(
        cluster(3),
        { sum: true },
        2,
      );
      const cipher = (await blindfold.encrypt(secKey, 123)) as number[][];
      await blindfold.decrypt(secKey, [
        [1, cipher[0][1]],
        [1, cipher[1][1]],
      ]);
      expectThrow();
    } catch (e) {
      expect(e).toStrictEqual(
        Error(
          "secret share index components must be distinct positive integers " +
            "less than the modulus",
        ),
      );
    }

    try {
      const secKey = await blindfold.SecretKey.generate(
        cluster(3),
        { sum: true },
        2,
      );
      const cipher = (await blindfold.encrypt(secKey, 123)) as number[][];
      await blindfold.decrypt(secKey, [[cipher[0][0], -1], cipher[1]]);
      expectThrow();
    } catch (e) {
      expect(e).toStrictEqual(
        Error(
          "secret share value components must be nonnegative integers " +
            "less than the modulus",
        ),
      );
    }
  });
});

/**
 * Tests consisting of end-to-end workflows involving secure computation.
 */
describe("end-to-end workflows involving secure computation", () => {
  test("end-to-end workflow involving secure summation for a single-node cluster", async () => {
    const secretKey = await blindfold.SecretKey.generate(cluster(1), {
      sum: true,
    });
    const publicKey = await blindfold.PublicKey.generate(secretKey);

    const a = (await blindfold.encrypt(publicKey, 123)) as string;
    const b = (await blindfold.encrypt(publicKey, 456)) as string;
    const c = (await blindfold.encrypt(publicKey, 789)) as string;

    const paillierPublicKey: paillierBigint.PublicKey =
      publicKey.material as paillierBigint.PublicKey;
    const aBigInt = BigInt(`0x${a}`);
    const bBigInt = BigInt(`0x${b}`);
    const cBigInt = BigInt(`0x${c}`);
    const rBigInt = paillierPublicKey.addition(
      paillierPublicKey.addition(
        paillierPublicKey.multiply(aBigInt, 2),
        paillierPublicKey.multiply(bBigInt, -1),
      ),
      cBigInt,
    );
    const decrypted = await blindfold.decrypt(secretKey, rBigInt.toString(16));
    expect(BigInt(decrypted as bigint)).toEqual(
      BigInt(2 * 123 + -1 * 456 + 789),
    );
  });

  test("end-to-end workflow involving secure summation for a multiple-node cluster", async () => {
    const secretKey = await blindfold.ClusterKey.generate(cluster(3), {
      sum: true,
    });

    const [a0, a1, a2] = (await blindfold.encrypt(secretKey, 123)) as number[];
    const [b0, b1, b2] = (await blindfold.encrypt(secretKey, 456)) as number[];
    const [c0, c1, c2] = (await blindfold.encrypt(secretKey, 789)) as number[];

    const modulus = _SECRET_SHARED_SIGNED_INTEGER_MODULUS;
    const [r0, r1, r2] = [
      Number(mod(BigInt(2 * a0 + -1 * b0 + c0), modulus)),
      Number(mod(BigInt(2 * a1 + -1 * b1 + c1), modulus)),
      Number(mod(BigInt(2 * a2 + -1 * b2 + c2), modulus)),
    ];
    const decrypted = await blindfold.decrypt(secretKey, [r0, r1, r2]);
    expect(BigInt(decrypted as bigint)).toEqual(
      BigInt(2 * 123 + -1 * 456 + 789),
    );
  });

  test("end-to-end workflow involving secure summation with a threshold for a multiple-node cluster", async () => {
    const secretKey = await blindfold.ClusterKey.generate(
      cluster(3),
      { sum: true },
      3,
    );

    const [a0, a1, a2] = (await blindfold.encrypt(secretKey, 123)) as [
      number,
      number,
    ][];
    const [b0, b1, b2] = (await blindfold.encrypt(secretKey, 456)) as [
      number,
      number,
    ][];
    const [c0, c1, c2] = (await blindfold.encrypt(secretKey, 789)) as [
      number,
      number,
    ][];

    const modulus = _SECRET_SHARED_SIGNED_INTEGER_MODULUS;
    const [r0, r1, r2] = shamirsAdd(
      shamirsAdd(
        shamirsMul([a0, a1, a2], 2, modulus),
        shamirsMul([b0, b1, b2], -1, modulus),
        modulus,
      ),
      [c0, c1, c2],
      modulus,
    );
    const decrypted = await blindfold.decrypt(secretKey, [r0, r1, r2]);
    expect(BigInt(decrypted as bigint)).toEqual(
      BigInt(2 * 123 + -1 * 456 + 789),
    );
  });
});

/**
 * Tests consisting of end-to-end workflows involving share allotment and unification.
 */
describe("end-to-end workflows involving share allotment and unification", () => {
  const cluster_ = cluster(3);

  test("allotment and unification of values for a multi-node cluster", async () => {
    for (const data of [true, 123, "abc", null]) {
      const secretKey = await blindfold.SecretKey.generate(cluster_, {
        store: true,
      });
      const shares = blindfold.allot(data);
      const decrypted = await blindfold.unify(secretKey, shares);
      expect(decrypted).toEqual(data);
    }
  });

  test("allotment and unification of arrays for a multi-node cluster", async () => {
    const data = [12n, 34n, 56n, 78n, 90n];
    const secretKey = await blindfold.SecretKey.generate(cluster_, {
      store: true,
    });
    const encrypted = [];
    for (let i = 0; i < data.length; i++) {
      encrypted.push({ "%allot": await blindfold.encrypt(secretKey, data[i]) });
    }
    const shares = blindfold.allot(encrypted) as object[][];
    expect(shares.length).toEqual(3);
    expect(shares.every((share) => share.length === data.length)).toEqual(true);

    const decrypted = await blindfold.unify(secretKey, shares);
    expect(decrypted).toEqual(data);
  });

  test("allotment and unification of simple objects for a multi-node cluster", async () => {
    const data: { [k: string]: bigint } = {
      a: 12n,
      b: 34n,
      c: 56n,
      d: 78n,
      e: 90n,
    };
    const secretKey = await blindfold.SecretKey.generate(cluster_, {
      store: true,
    });
    const encrypted: { [k: string]: object } = {};
    for (const key in data) {
      encrypted[key] = {
        "%allot": await blindfold.encrypt(secretKey, data[key]),
      };
    }
    const shares = blindfold.allot(encrypted) as object[][];
    expect(shares.length).toEqual(3);

    const keys = Object.keys(data);
    expect(
      shares.every((share) => equalKeys(Object.keys(share), keys)),
    ).toEqual(true);

    const decrypted = await blindfold.unify(secretKey, shares);
    expect(decrypted).toEqual(data);
  });

  test("allotment and unification of mixed objects for a multi-node cluster", async () => {
    const data: { [k: string]: [boolean, string, bigint] } = {
      a: [true, "v", 12n],
      b: [false, "w", 34n],
      c: [true, "x", 56n],
      d: [false, "y", 78n],
      e: [true, "z", 90n],
    };
    const secretKey = await blindfold.SecretKey.generate(cluster_, {
      store: true,
    });
    const encrypted: { [k: string]: object } = {};
    for (const key in data) {
      encrypted[key] = [
        data[key][0],
        data[key][1],
        { "%allot": await blindfold.encrypt(secretKey, data[key][2]) },
      ];
    }
    const shares = blindfold.allot(encrypted) as object[][];
    expect(shares.length).toEqual(3);

    const decrypted = await blindfold.unify(secretKey, shares);
    expect(toJSON(decrypted)).toEqual(toJSON(data));
  });

  test("allotment and unification of objects with nested arrays of shares for a multi-node cluster", async () => {
    const data: { [k: string]: object | null | number } = {
      a: [1n, [2n, 3n]],
      b: [4n, [5n, 6n]],
      c: null,
      d: 1.23,
    };
    const secretKey = await blindfold.SecretKey.generate(cluster_, {
      store: true,
    });
    const encrypted: { [k: string]: object | null | number } = {};
    for (const key of ["a", "b"]) {
      encrypted[key] = {
        "%allot": [
          await blindfold.encrypt(secretKey, (data[key] as bigint[])[0]),
          [
            await blindfold.encrypt(secretKey, (data[key] as bigint[][])[1][0]),
            await blindfold.encrypt(secretKey, (data[key] as bigint[][])[1][1]),
          ],
        ],
      };
    }
    encrypted.c = null;
    encrypted.d = 1.23;
    const shares = blindfold.allot(encrypted) as {
      [key: string]: string | object;
    }[];
    expect(shares.length).toEqual(3);

    // Introduce entries that should be ignored.
    shares[0]._created = "123";
    shares[1]._created = "456";
    shares[2]._created = "789";
    shares[0]._updated = "ABC";
    shares[1]._updated = "DEF";
    shares[2]._updated = "GHI";

    const decrypted = await blindfold.unify(secretKey, shares);
    expect(toJSON(decrypted)).toEqual(toJSON(data));
  });
});

/**
 * Tests verifying that allotment/unification functions return expected errors.
 */
describe("errors involving allotment and unification functions", () => {
  test("errors that can occur during allotment", async () => {
    try {
      blindfold.allot({ age: { "%allot": [1, 2, 3], extra: "ABC" } });
      expectThrow();
    } catch (e) {
      expect(e).toStrictEqual(Error("allotment must only have one key"));
    }

    try {
      blindfold.allot({
        id: 0,
        age: { "%allot": [1, 2, 3] },
        dat: { loc: { "%allot": [4, 5] } },
      });
      expectThrow();
    } catch (e) {
      expect(e).toStrictEqual(
        Error("number of shares in subdocument is not consistent"),
      );
    }

    try {
      blindfold.allot([
        0,
        { "%allot": [1, 2, 3] },
        { loc: { "%allot": [4, 5] } },
      ]);
      expectThrow();
    } catch (e) {
      expect(e).toStrictEqual(
        Error("number of shares in subdocument is not consistent"),
      );
    }
  });

  test("errors that can occur during unification", async () => {
    const secretKey = await blindfold.SecretKey.generate(cluster(3), {
      store: true,
    });

    try {
      await blindfold.unify(secretKey, [123, "abc"]);
      expectThrow();
    } catch (e) {
      expect(e).toStrictEqual(
        Error("array of compatible document shares expected"),
      );
    }
  });
});
