/** Google Confidential Space token issuer. */
export const GOOGLE_CONFIDENTIAL_SPACE_ISSUER =
  "https://confidentialcomputing.googleapis.com" as const;

/**
 * SHA-256 fingerprint of the Google Confidential Space PKI root certificate.
 * The offline verifier deliberately does not fall back to network JWKS.
 */
export const GOOGLE_CONFIDENTIAL_SPACE_PKI_ROOT_SHA256 =
  "14:8B:29:38:21:BB:0C:6A:31:7F:41:3C:8B:A4:75:81:40:91:CB:22:D4:9B:9E:3C:94:19:8D:B8:E8:F8:6C:39" as const;
