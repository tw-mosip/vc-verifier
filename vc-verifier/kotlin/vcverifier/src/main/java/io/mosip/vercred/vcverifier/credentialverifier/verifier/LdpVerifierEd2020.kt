package io.mosip.vercred.vcverifier.credentialverifier.verifier

import android.security.KeyStoreException
import android.util.Log
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.node.ObjectNode
import com.nimbusds.jose.JWSObject
import foundation.identity.jsonld.ConfigurableDocumentLoader
import foundation.identity.jsonld.JsonLDObject
import info.weboftrust.ldsignatures.LdProof
import info.weboftrust.ldsignatures.canonicalizer.URDNA2015Canonicalizer
import info.weboftrust.ldsignatures.util.JWSUtil
import io.ipfs.multibase.Base58
import io.mosip.vercred.vcverifier.signature.SignatureVerifier
import io.mosip.vercred.vcverifier.CredentialVerifier
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.ED25519_ALGORITHM
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.RSA_ALGORITHM
import io.mosip.vercred.vcverifier.exception.PublicKeyNotFoundException
import io.mosip.vercred.vcverifier.exception.SignatureVerificationException
import io.mosip.vercred.vcverifier.exception.UnknownException
import io.mosip.vercred.vcverifier.signature.impl.ED25519SignatureVerifierImpl
import io.mosip.vercred.vcverifier.signature.impl.PS256SignatureVerifierImpl
import io.mosip.vercred.vcverifier.signature.impl.RS256SignatureVerifierImpl
import okhttp3.OkHttpClient
import okhttp3.Request
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.util.io.pem.PemReader
import java.io.IOException
import java.io.StringReader
import java.net.URI
import java.security.KeyFactory
import java.security.KeyManagementException
import java.security.NoSuchAlgorithmException
import java.security.PublicKey
import java.security.Security
import java.security.cert.CertificateException
import java.security.spec.X509EncodedKeySpec
import java.util.Objects

class LdpVerifierEd2020 {

    private val tag: String = CredentialVerifier::class.java.name
    private var provider: BouncyCastleProvider = BouncyCastleProvider()

    init {
        Security.addProvider(provider);
    }


    fun verify(credential: String): Boolean {

        Log.i(tag, "Received Credentials Verification - Start")
        val confDocumentLoader: ConfigurableDocumentLoader = getConfigurableDocumentLoader()
        val vcJsonLdObject: JsonLDObject = JsonLDObject.fromJson(credential)
        vcJsonLdObject.documentLoader = confDocumentLoader
        val ldProofWithProof: LdProof = LdProof.getFromJsonLDObject(vcJsonLdObject)
        return try {
            val canonicalizer = URDNA2015Canonicalizer()

            val canonicalHashBytes: ByteArray = canonicalizer.canonicalize(ldProofWithProof, vcJsonLdObject)
            val proofValue: String = ldProofWithProof.proofValue.substring(1)
            val signature = Base58.decode(proofValue)

            val publicKeyObj = getPublicKeyFromVerificationMethod(ldProofWithProof.verificationMethod)
            if (Objects.isNull(publicKeyObj)) {
                throw PublicKeyNotFoundException("Public key object is null")
            }

            //TODO: Get the verifier for ED25519 and verify the data
            /*val signatureVerifier: SignatureVerifier = SIGNATURE_VERIFIER[CredentialVerifierConstants.JWS_EDDSA_SIGN_ALGO_CONST]!!
            signatureVerifier.verify(publicKeyObj!!, canonicalHashBytes, proofBytes, provider)*/
            return true
        } catch (e: Exception) {
            when (e) {
                is PublicKeyNotFoundException,
                is SignatureVerificationException -> throw e
                else -> {
                    throw UnknownException("Error while doing verification of verifiable credential")
                }
            }
        }
    }

    @Throws(CertificateException::class, KeyStoreException::class, KeyManagementException::class)
    private fun getPublicKeyFromVerificationMethod(verificationMethod:  URI ): PublicKey? {
        return try {
            // TODO:  First resolve the did and then make api call in case the document is not loaded else we can skip this step
            val okHttpClient = OkHttpClient.Builder().build().newBuilder().build()
            val request = Request.Builder()
                .url(verificationMethod.toURL())
                .get()
                .build()

            val response = okHttpClient.newCall(request).execute()
            response.body?.let { responseBody ->
                val objectMapper = ObjectMapper()
                val jsonNode = objectMapper.readTree(responseBody.string())
                if (jsonNode.isObject) {
                    val responseObjectNode = jsonNode as ObjectNode
                    val publicKeyMultibase=responseObjectNode[CredentialVerifierConstants.PUBLIC_KEY_MULTIBASE].asText()
                    val rawPublicKeyByteArray: ByteArray = Base58.decode(publicKeyMultibase.substring(1))
                    val pubKeySpec = X509EncodedKeySpec(rawPublicKeyByteArray)
                    val keyFactory = KeyFactory.getInstance("Ed25519", provider)
                    keyFactory.generatePublic(pubKeySpec)
                } else null
            }
        } catch (e: Exception) {
            Log.e(tag, "Error Generating public key object", e)
            null
        }
    }

    @Throws(
        CertificateException::class,
        IOException::class,
        KeyStoreException::class,
        NoSuchAlgorithmException::class,
        KeyManagementException::class
    )
    private fun getConfigurableDocumentLoader(): ConfigurableDocumentLoader {
        val confDocumentLoader = ConfigurableDocumentLoader()
        confDocumentLoader.isEnableHttps = true
        confDocumentLoader.isEnableHttp = true
        confDocumentLoader.isEnableFile = false
        return confDocumentLoader
    }
}



//--------------------------

/*package io.mosip.vercred.vcverifier.credentialverifier.verifier

import android.security.KeyStoreException
import android.util.Log
import io.ipfs.multibase.Base58
import net.i2p.crypto.eddsa.EdDSAPublicKey
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.node.ObjectNode
import foundation.identity.jsonld.ConfigurableDocumentLoader
import foundation.identity.jsonld.JsonLDObject
import info.weboftrust.ldsignatures.LdProof
import info.weboftrust.ldsignatures.canonicalizer.URDNA2015Canonicalizer
import io.mosip.vercred.vcverifier.CredentialVerifier
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.ED25519_ALGORITHM
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.RSA_ALGORITHM
import io.mosip.vercred.vcverifier.exception.PublicKeyNotFoundException
import io.mosip.vercred.vcverifier.exception.SignatureVerificationException
import io.mosip.vercred.vcverifier.exception.UnknownException
import io.mosip.vercred.vcverifier.signature.SignatureVerifier
import io.mosip.vercred.vcverifier.signature.impl.ED25519SignatureVerifierImpl
import io.mosip.vercred.vcverifier.signature.impl.PS256SignatureVerifierImpl
import io.mosip.vercred.vcverifier.signature.impl.RS256SignatureVerifierImpl
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.io.IOException
import java.net.URI
import java.security.KeyFactory
import java.security.KeyManagementException
import java.security.NoSuchAlgorithmException
import java.security.PublicKey
import java.security.Security
import java.security.cert.CertificateException
import java.security.spec.X509EncodedKeySpec
import java.util.Objects

class LdpVerifierEd2020 {

    private val tag: String = CredentialVerifier::class.java.name
    private var provider: BouncyCastleProvider = BouncyCastleProvider()

    init {
        Security.addProvider(provider);
    }

    private val SIGNATURE_VERIFIER: Map<String, SignatureVerifier> = mapOf(
        CredentialVerifierConstants.JWS_PS256_SIGN_ALGO_CONST to PS256SignatureVerifierImpl(),
        CredentialVerifierConstants.JWS_RS256_SIGN_ALGO_CONST to RS256SignatureVerifierImpl(),
        CredentialVerifierConstants.JWS_EDDSA_SIGN_ALGO_CONST to ED25519SignatureVerifierImpl()
    )

    private val PUBLIC_KEY_ALGORITHM: Map<String, String> = mapOf(
        CredentialVerifierConstants.JWS_PS256_SIGN_ALGO_CONST to RSA_ALGORITHM,
        CredentialVerifierConstants.JWS_RS256_SIGN_ALGO_CONST to RSA_ALGORITHM,
        CredentialVerifierConstants.JWS_EDDSA_SIGN_ALGO_CONST to ED25519_ALGORITHM
    )

    fun verify(credential: String): Boolean {

        Log.i(tag, "Received Credentials Verification - Start")
        val confDocumentLoader: ConfigurableDocumentLoader = getConfigurableDocumentLoader()
        val vcJsonLdObject: JsonLDObject = JsonLDObject.fromJson(credential)
        vcJsonLdObject.documentLoader = confDocumentLoader
        val ldProofWithProof: LdProof = LdProof.getFromJsonLDObject(vcJsonLdObject)
        return try {
            val canonicalizer = URDNA2015Canonicalizer()
            val canonicalHashBytes: ByteArray =
                canonicalizer.canonicalize(ldProofWithProof, vcJsonLdObject)
            val proofValue: String = ldProofWithProof.getProofValue().substring(1)
            val proofBytes = Base58.decode(proofValue)
            val publicKeyJsonUri: URI = ldProofWithProof.verificationMethod
            val publicKeyObj = getPublicKeyFromVerificationMethod(
                publicKeyJsonUri,
                PUBLIC_KEY_ALGORITHM[CredentialVerifierConstants.JWS_EDDSA_SIGN_ALGO_CONST]!!
            )
            if (Objects.isNull(publicKeyObj)) {
                throw PublicKeyNotFoundException("Public key object is null")
            }
            val signatureVerifier: SignatureVerifier =
                SIGNATURE_VERIFIER[CredentialVerifierConstants.JWS_EDDSA_SIGN_ALGO_CONST]!!
            signatureVerifier.verify(publicKeyObj!!, canonicalHashBytes, proofBytes, provider)
        } catch (e: Exception) {
            when (e) {
                is PublicKeyNotFoundException,
                is SignatureVerificationException,
                -> throw e

                else -> {
                    throw UnknownException("Error while doing verification of verifiable credential")
                }
            }
        }
    }

    @Throws(CertificateException::class, KeyStoreException::class, KeyManagementException::class)
    private fun getPublicKeyFromVerificationMethod(
        publicKeyJsonUri: URI,
        algo: String,
    ): PublicKey? {
        return try {
            // Mocked JSON response (this should be the public key JSON you're expecting)
            val mockedResponse = """
            {
              "@context": [
                "https://www.w3.org/ns/did/v1"
              ],
              "id": "did:web:api.dev1.mosip.net:identity-service:8ebda1d0-665b-4bb7-abc7-d4bf56b6ee09",
              "alsoKnownAs": [
                "testUUID",
                "test@gmail.com"
              ],
              "service": [],
              "verificationMethod": [
                {
                  "id": "did:web:api.dev1.mosip.net:identity-service:8ebda1d0-665b-4bb7-abc7-d4bf56b6ee09#key-0",
                  "type": "Ed25519VerificationKey2020",
                  "@context": "https://w3id.org/security/suites/ed25519-2020/v1",
                  "controller": "did:web:api.dev1.mosip.net:identity-service:8ebda1d0-665b-4bb7-abc7-d4bf56b6ee09",
                  "publicKeyMultibase": "z6MkgyqqhDH2wkp8K4uKYak6LYwAmue4XRnjP5LA2v62M3NL"
                }
              ],
              "authentication": [
                "did:web:api.dev1.mosip.net:identity-service:8ebda1d0-665b-4bb7-abc7-d4bf56b6ee09#key-0"
              ],
              "assertionMethod": [
                "did:web:api.dev1.mosip.net:identity-service:8ebda1d0-665b-4bb7-abc7-d4bf56b6ee09#key-0"
              ]
            }
        """.trimIndent()

            // ObjectMapper to parse the mocked JSON response
            val objectMapper = ObjectMapper()
            val jsonNode = objectMapper.readTree(mockedResponse)
            if (jsonNode.isObject) {
                val responseObjectNode = jsonNode as ObjectNode
                val verificationMethod = responseObjectNode["verificationMethod"]
                val publicKeyMultibase = verificationMethod[0]["publicKeyMultibase"].asText()

                // Step 1: Remove the 'z' prefix (indicating Base58 encoding)
                val keyData = publicKeyMultibase.substring(1)

                // Step 2: Decode Base58
                val rawPublicKeyWithHeader = Base58.decode(keyData)

                // Step 3: Remove the 2-byte multicodec header (0xed01)
                if (rawPublicKeyWithHeader.size > 2 && rawPublicKeyWithHeader[0] == 0xed.toByte() && rawPublicKeyWithHeader[1] == 0x01.toByte()) {
                    val rawPublicKey = rawPublicKeyWithHeader.copyOfRange(2, rawPublicKeyWithHeader.size)

                    // Create the public key from the 32-byte Ed25519 public key
                    val pubKeySpec = EdDSAPublicKeySpec(rawPublicKey, EdDSANamedCurveTable.getByName("Ed25519"))


                    return EdDSAPublicKey(pubKeySpec)
                }
            }
            null
        } catch (e: Exception) {
            Log.e("PublicKeyError", "Error Generating public key object", e)
            null
        }
    }


    @Throws(
        CertificateException::class,
        IOException::class,
        KeyStoreException::class,
        NoSuchAlgorithmException::class,
        KeyManagementException::class
    )
    private fun getConfigurableDocumentLoader(): ConfigurableDocumentLoader {
        val confDocumentLoader = ConfigurableDocumentLoader()
        confDocumentLoader.isEnableHttps = true
        confDocumentLoader.isEnableHttp = true
        confDocumentLoader.isEnableFile = false
        return confDocumentLoader
    }



}
*/
