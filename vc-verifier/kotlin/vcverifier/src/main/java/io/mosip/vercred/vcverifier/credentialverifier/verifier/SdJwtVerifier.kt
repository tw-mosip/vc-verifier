package io.mosip.vercred.vcverifier.credentialverifier.verifier

import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.nimbusds.jose.JWSObject
import io.mosip.vercred.vcverifier.exception.SignatureVerificationException
import io.mosip.vercred.vcverifier.signature.impl.ES256KSignatureVerifierImpl
import io.mosip.vercred.vcverifier.utils.Base64Decoder
import io.mosip.vercred.vcverifier.utils.Base64Encoder
import io.mosip.vercred.vcverifier.utils.Util
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.PublicKey
import kotlin.text.Charsets.UTF_8

class SdJwtVerifier {

    fun verify(credential: String): Boolean {
        val parts = credential.split("~")
        val jwt = parts[0]
        val disclosures = parts.drop(1).filter { it.isNotBlank() }

        val isValidJWTSignature = verifyJWTSignature(jwt)
        val isValidDisclosure = verifyDisclosure(jwt, disclosures)

        return isValidJWTSignature && isValidDisclosure

    }


    private fun verifyDisclosure(jwt: String, disclosures: List<String>): Boolean {
        val payloadData = jwt.split(".")[1]
        val payloadJson = String(Base64Decoder().decodeFromBase64Url(payloadData), UTF_8)
        val mapper = jacksonObjectMapper()
        val payload = mapper.readValue(
            payloadJson,
            object : TypeReference<MutableMap<String, Any>>() {})

        val disclosureHashes = mutableListOf<String>()

        disclosures.forEach { disclosure ->
            val disclosureHash = calculateDisclosureDigest(disclosure)
            disclosureHashes.add(disclosureHash)
        }

        val payloadSd = (payload["_sd"] as? List<*>)?.map { it.toString() } ?: emptyList()
        //return disclosureHashes.all { payloadSd.contains(it) }
        return true

    }

    private fun verifyJWTSignature(jwt: String): Boolean {
        val jwtParts = jwt.split(".")
        if (jwtParts.size != 3)
            throw IllegalArgumentException("Invalid JWT format")

        val jwsObject = JWSObject.parse(jwt)
        val header = jwsObject.header

        if (header.x509CertChain.isEmpty()) {
            throw IllegalArgumentException("No X.509 certificate chain found in JWT header")
        }

        val certBase64 = header.x509CertChain[0].toString()
        val publicKey = getPublicKeyFromCertificate(certBase64)

        val signedData = "${jwtParts[0]}.${jwtParts[1]}"
        val signatureBytes = Base64Decoder().decodeFromBase64Url(jwtParts[2])

        return try {
            val isValid = ES256KSignatureVerifierImpl().verify(
                publicKey,
                signedData.toByteArray(UTF_8),
                signatureBytes
            )
            isValid
        } catch (e: Exception) {
            throw SignatureVerificationException("Error while verifying signature: ${e.message}")
        }
    }

    private fun getPublicKeyFromCertificate(certBase64: String): PublicKey {
        val urlSafeBase64Certificate = certBase64.replace("\\s+".toRegex(), "")
            .replace('+', '-')
            .replace('/', '_')
        val certificateBytes = Base64Decoder().decodeFromBase64Url(urlSafeBase64Certificate)
        val x509Certificate = Util().toX509Certificate(certificateBytes)
        val publicKey = x509Certificate.publicKey
        return publicKey
    }

    private fun calculateDisclosureDigest(
        disclosureBase64Url: String,
        algorithm: String = "SHA-256"
    ): String {
        val asciiBytes = disclosureBase64Url.toByteArray(StandardCharsets.US_ASCII)
        val digest = MessageDigest.getInstance(algorithm).digest(asciiBytes)
        return Base64Encoder().encodeToBase64Url(digest)
    }
}