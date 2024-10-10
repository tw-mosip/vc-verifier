package io.mosip.vercred.vcverifier.constants


object CredentialVerifierConstants {
    val SIGNATURE_SUITE_TERM = arrayOf("RsaSignature2018", "Ed25519Signature2018")
    const val PUBLIC_KEY_PEM = "publicKeyPem"
    const val JWS_RS256_SIGN_ALGO_CONST = "RS256"
    const val RS256_ALGORITHM = "SHA256withRSA"
    const val PS256_ALGORITHM_ANDROID: String = "SHA256withRSA/PSS"
    const val PS256_ALGORITHM: String = "RSASSA-PSS"
    const val PSS_PARAM_SHA_256 = "SHA-256"
    const val PSS_PARAM_MGF1 = "MGF1"
    const val PSS_PARAM_SALT_LEN = 32
    const val PSS_PARAM_TF = 1
    const val ED25519_ALGORITHM = "Ed25519"
    const val RSA_ALGORITHM = "RSA"
    const val JWS_PS256_SIGN_ALGO_CONST: String = "PS256"
    const val JWS_EDDSA_SIGN_ALGO_CONST = "EdDSA"
}