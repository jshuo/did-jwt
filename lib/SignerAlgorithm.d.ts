import type { SignerAlgorithm } from './JWT.js';
export declare function ES256SignerAlg(recoverable?: boolean): SignerAlgorithm;
export declare function ES256KSignerAlg(recoverable?: boolean): SignerAlgorithm;
export declare function Ed25519SignerAlg(): SignerAlgorithm;
declare function SignerAlg(alg: string): SignerAlgorithm;
export default SignerAlg;
//# sourceMappingURL=SignerAlgorithm.d.ts.map