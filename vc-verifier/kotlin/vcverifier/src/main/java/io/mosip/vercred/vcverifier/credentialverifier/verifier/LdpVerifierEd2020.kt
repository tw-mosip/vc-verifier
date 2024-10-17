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
            val canonicalHashBytes: ByteArray = canonicalizer.canonicalize(ldProofWithProof, vcJsonLdObject)
            val proofValue: String = ldProofWithProof.getProofValue().substring(1)
            val proofBytes=convertBase58toByteArray(proofValue)
            val publicKeyObj = getPublicKeyFromVerificationMethod(publicKeyJsonUri, PUBLIC_KEY_ALGORITHM[CredentialVerifierConstants.JWS_EDDSA_SIGN_ALGO_CONST]!!)
            if (Objects.isNull(publicKeyObj)) {
                throw PublicKeyNotFoundException("Public key object is null")
            }
            val signatureVerifier: SignatureVerifier = SIGNATURE_VERIFIER[CredentialVerifierConstants.JWS_EDDSA_SIGN_ALGO_CONST]!!
            signatureVerifier.verify(publicKeyObj!!, canonicalHashBytes, proofBytes, provider)
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
    private fun getPublicKeyFromVerificationMethod(publicKeyJsonUri: URI, algo: String ): PublicKey? {
        return try {
            val okHttpClient = OkHttpClient.Builder().build().newBuilder().build()
            val request = Request.Builder()
                .url(publicKeyJsonUri.toURL())
                .get()
                .build()

            val response = okHttpClient.newCall(request).execute()
            response.body?.let { responseBody ->
                val objectMapper = ObjectMapper()
                val jsonNode = objectMapper.readTree(responseBody.string())
                if (jsonNode.isObject) {
                    val responseObjectNode = jsonNode as ObjectNode
                    val publicKeyMultibase=responseObjectNode[CredentialVerifierConstants.PUBLIC_KEY_MULTIBASE].asText()
                    val publicKeyMultibaseHeader=publicKeyMultibase[0];
                    val rawPublicKeyByteArray=[]
                    if(publicKeyMultibaseHeader == 'z'){
                         rawPublicKeyByteArray=convertBase58ToByteArray(publicKeyMultibase.substring(1))
                    }
                    else{
                        rawPublicKeyByteArray=convertBase64ToByteArray(publicKeyMultibase.substring(1))
                    }
                    val pubKeySpec = X509EncodedKeySpec(rawPublicKeyByteArray)
                    val keyFactory = KeyFactory.getInstance(algo, provider)
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