import { Signer } from '../JWT.js';
/**
 *  Creates a configured signer function for signing data using the ES256 (secp256r1 + sha256) algorithm.
 *
 *  The signing function itself takes the data as a `Uint8Array` or `string` and returns a `base64Url`-encoded signature
 *
 *  @example
 *  ```typescript
 *  const sign: Signer = ES256Signer(process.env.PUF_HSM_REMOTE_URL)
 *  const signature: string = await sign(data)
 *  ```
 *
 *  @param    {String}    PUF_HSM_REMOTE_URL   a puf hsm url as `Uint8Array`
 *  @return   {Function}               a configured signer function `(data: string | Uint8Array): Promise<string>`
 */
export declare function ES256HSMSigner(pufHsmRemoteUrl: string): Signer;
//# sourceMappingURL=ES256HSMSigner.d.ts.map