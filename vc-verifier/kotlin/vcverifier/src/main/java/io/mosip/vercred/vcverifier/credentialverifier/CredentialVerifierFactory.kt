package io.mosip.vercred.vcverifier.credentialverifier

import io.mosip.vercred.vcverifier.constants.CredentialFormat
import io.mosip.vercred.vcverifier.constants.CredentialFormat.*
import io.mosip.vercred.vcverifier.credentialverifier.types.LdpVcCredentialVerifier
import io.mosip.vercred.vcverifier.credentialverifier.types.MsoMdocCredentialVerifier

class CredentialVerifierFactory {
    fun verify(credential: String, credentialFormat: CredentialFormat): Boolean {
        return when (credentialFormat) {
            LDP_VC -> LdpVcCredentialVerifier().verify(
                credential = credential
            )

            MSO_MDOC -> MsoMdocCredentialVerifier().verify(credential)
        }
    }
}
