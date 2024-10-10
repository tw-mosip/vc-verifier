package io.mosip.vercred.signature.impl;

import io.mosip.vercred.contant.CredentialVerifierConstants;
import io.mosip.vercred.exception.SignatureVerificationException;
import io.mosip.vercred.signature.SignatureVerifier;

import java.security.*;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

public class PS256SignatureVerifierImpl implements SignatureVerifier {

    @Override
    public Boolean verify(PublicKey publicKey, byte[] signData, byte[] signature) {
        try {
            Signature psSignature = Signature.getInstance(CredentialVerifierConstants.PS256_ALGORITHM);

            PSSParameterSpec pssParamSpec = new PSSParameterSpec(CredentialVerifierConstants.PSS_PARAM_SHA_256, CredentialVerifierConstants.PSS_PARAM_MGF1,
                    MGF1ParameterSpec.SHA256, CredentialVerifierConstants.PSS_PARAM_SALT_LEN, CredentialVerifierConstants.PSS_PARAM_TF);
            psSignature.setParameter(pssParamSpec);

            psSignature.initVerify(publicKey);
            psSignature.update(signData);
            return psSignature.verify(signature);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException | InvalidAlgorithmParameterException e) {
            throw new SignatureVerificationException("Error while doing signature verification using PS256 algorithm");
        }
    }
}
