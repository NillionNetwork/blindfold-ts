declare module "crypto-browserify" {
  // biome-ignore lint/style/useNodejsImportProtocol: webpack doesn't support node: protocol
  import type { BinaryLike } from "crypto";

  export interface Hmac {
    update(data: BinaryLike): this;
    digest(): Buffer;
  }

  export function createHmac(algorithm: string, key: BinaryLike): Hmac;
}
