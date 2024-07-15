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
 *  const sign: Signer = ES256Signer(process.env.PUF_HSM_REMOTE_URL)
 *  const signature: string = await sign(data)
 *  ```
 *
 *  @param    {String}    PUF_HSM_REMOTE_URL   a puf hsm url as `Uint8Array`
 *  @return   {Function}               a configured signer function `(data: string | Uint8Array): Promise<string>`
 */
export function ES256HSMSigner(pufHsmRemoteUrl: string): Signer {
  return async (data: string | Uint8Array): Promise<string> => {
    try {
      const response = await fetch(pufHsmRemoteUrl+'/pufs_p256_sign_js', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ content: sha256(data) }),
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      const signature = response.text()
      return toJose({
        r: leftpad(signature.r.toString(16)),
        s: leftpad(signature.s.toString(16)),
      })

    } catch (error) {
      console.error("Error summarizing text:", error);
      throw error; // Handle the error appropriately
    }


  }
}
