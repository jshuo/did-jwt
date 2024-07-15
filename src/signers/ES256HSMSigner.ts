import { leftpad, toJose } from '../util.js'
import { Signer } from '../JWT.js'
import { sha256 } from '../Digest.js'

/**
 *  Creates a configured signer function for signing data using the ES256 (secp256r1 + sha256) algorithm.
 *
 *  The signing function itself takes the data as a `Uint8Array` or `string` and returns a `base64Url`-encoded signature
 *
 *  @example
 *  ```typescript
 *  const sign: Signer = ES256HSMSigner(process.env.PUF_HSM_REMOTE_URL)
 *  const signature: string = await sign(data)
 *  ```
 *
 *  @param    {String}    PUF_HSM_REMOTE_URL   a puf hsm url as `Uint8Array`
 *  @return   {Function}               a configured signer function `(data: string | Uint8Array): Promise<string>`
 */

function uint8ArrayToHex(uint8Array: Uint8Array) {
  return Array.from(uint8Array, byte => byte.toString(16).padStart(2, '0')).join('');
}

export function ES256HSMSigner(pufHsmRemoteUrl: string): Signer {
  return async (data: string | Uint8Array): Promise<string> => {
    try {
      const hashArray = sha256(data);
      const hashHex = uint8ArrayToHex(hashArray);

      const response = await fetch(`${pufHsmRemoteUrl}/pufs_p256_sign_js`, {
        method: 'POST',
        headers: {
          'Content-Type': 'text/plain',
        },
        body: hashHex,
      });
      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`HTTP error! status: ${response.status}, response: ${errorText}`);
      }

      const signature = await response.json();
      return toJose({
        r: leftpad(signature.sig.r.toString(16)),
        s: leftpad(signature.sig.s.toString(16)),
      });

    } catch (error) {
      console.error("Error signing data:", error);
      throw error; // Handle the error appropriately
    }
  }
}
