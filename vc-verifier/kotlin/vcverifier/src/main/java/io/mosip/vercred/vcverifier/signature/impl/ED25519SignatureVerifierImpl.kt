package io.mosip.vercred.vcverifier.signature.impl

import android.annotation.TargetApi
import android.os.Build
import io.mosip.vercred.vcverifier.signature.SignatureVerifier
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants
import io.mosip.vercred.vcverifier.exception.SignatureVerificationException
import net.i2p.crypto.eddsa.EdDSAEngine
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.PublicKey
import java.security.Signature

class ED25519SignatureVerifierImpl : SignatureVerifier {


    @TargetApi(Build.VERSION_CODES.TIRAMISU)
    override fun verify(publicKey: PublicKey, signData: ByteArray, signature: ByteArray, provider: BouncyCastleProvider): Boolean {
        try {
//            val ed25519Signature =
//                Signature.getInstance(CredentialVerifierConstants.ED25519_ALGORITHM, provider)
//                    /*.apply {
//                    initVerify(publicKey)
//                    update(signData)
//                    verify(signature)
//                }*/
            val eddsaEngine = EdDSAEngine()
            eddsaEngine.initVerify(publicKey)

            // Step 3: Update the engine with the data to verify
            eddsaEngine.update(signData)

            // Step 4: Verify the signature
            return eddsaEngine.verify(signature)

        } catch (e: Exception) {
            throw SignatureVerificationException("Error while doing signature verification using ED25519 algorithm")
        }
    }
}