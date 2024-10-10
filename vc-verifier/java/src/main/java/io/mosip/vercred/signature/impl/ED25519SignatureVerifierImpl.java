package io.mosip.vercred.signature.impl;

import io.mosip.vercred.contant.CredentialVerifierConstants;
import io.mosip.vercred.exception.SignatureVerificationException;
import io.mosip.vercred.signature.SignatureVerifier;

import java.security.*;

public class ED25519SignatureVerifierImpl implements SignatureVerifier {
    @Override
    public Boolean verify(PublicKey publicKey, byte[] signData, byte[] signature) {
        try {
            Signature ed25519Signature = Signature.getInstance(CredentialVerifierConstants.ED25519_ALGORITHM);
            ed25519Signature.initVerify(publicKey);
            ed25519Signature.update(signData);
            return ed25519Signature.verify(signature);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new SignatureVerificationException("Error while doing signature verification using ED25519 algorithm");
        }
    }
}
