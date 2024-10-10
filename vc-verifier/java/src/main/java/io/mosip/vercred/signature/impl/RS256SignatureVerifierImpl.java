package io.mosip.vercred.signature.impl;

import io.mosip.vercred.contant.CredentialVerifierConstants;
import io.mosip.vercred.exception.SignatureVerificationException;
import io.mosip.vercred.signature.SignatureVerifier;

import java.security.*;

public class RS256SignatureVerifierImpl implements SignatureVerifier {
    @Override
    public Boolean verify(PublicKey publicKey, byte[] signData, byte[] signature) {
        try {
            Signature rsSignature = Signature.getInstance(CredentialVerifierConstants.RS256_ALGORITHM);
            rsSignature.initVerify(publicKey);
            rsSignature.update(signData);
            return rsSignature.verify(signature);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new SignatureVerificationException("Error while doing signature verification using RS256 algorithm");
        }
    }
}
