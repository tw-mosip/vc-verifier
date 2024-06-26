package io.mosip.vercred;

import foundation.identity.jsonld.JsonLDException;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.text.ParseException;

class CredentialsVerifierTest {
    @Test
    void shouldTestCredential() throws JsonLDException, GeneralSecurityException, IOException, ParseException {
        String credential = "<hardcoded-credential>";
        boolean isCredentialVerified = new CredentialsVerifier().verifyCredentials(credential);
        assert isCredentialVerified;
    }
}
