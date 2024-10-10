package io.mosip.vercred;

import java.io.IOException;
import java.io.StringReader;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import com.apicatalog.jsonld.JsonLdError;
import com.apicatalog.jsonld.document.JsonDocument;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.JWSObject;

import io.mosip.vercred.exception.*;
import io.mosip.vercred.signature.SignatureVerifier;
import io.mosip.vercred.signature.impl.ED25519SignatureVerifierImpl;
import io.mosip.vercred.signature.impl.PS256SignatureVerifierImpl;
import io.mosip.vercred.signature.impl.RS256SignatureVerifierImpl;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpMethod;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestTemplate;

import foundation.identity.jsonld.ConfigurableDocumentLoader;
import foundation.identity.jsonld.JsonLDObject;
import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.canonicalizer.URDNA2015Canonicalizer;
import info.weboftrust.ldsignatures.util.JWSUtil;
import io.mosip.vercred.contant.CredentialVerifierConstants;

public class CredentialsVerifier {

    Logger CredVerifierLogger = LoggerFactory.getLogger(CredentialsVerifier.class);

    @Value("#{${mosip.vercred.verify.context.url.map}}")
	private Map<String, String> vcContextUrlMap;

    @Value("${mosip.config.server.file.storage.uri:}")
	private String configServerFileStorageUrl;

    private static final Map<String, SignatureVerifier> SIGNATURE_VERIFIER = new HashMap<>();

    static {
        SIGNATURE_VERIFIER.put(CredentialVerifierConstants.JWS_PS256_SIGN_ALGO_CONST, new PS256SignatureVerifierImpl());
        SIGNATURE_VERIFIER.put(CredentialVerifierConstants.JWS_RS256_SIGN_ALGO_CONST, new RS256SignatureVerifierImpl());
        SIGNATURE_VERIFIER.put(CredentialVerifierConstants.JWS_EDDSA_SIGN_ALGO_CONST, new ED25519SignatureVerifierImpl());
    }

    public boolean verifyCredentials(String credentials) {
        CredVerifierLogger.info("Received Credentials Verification - Start");
        ConfigurableDocumentLoader confDocumentLoader = getConfigurableDocumentLoader();

        JsonLDObject vcJsonLdObject = JsonLDObject.fromJson(credentials);
        vcJsonLdObject.setDocumentLoader(confDocumentLoader);

        LdProof ldProofWithJWS = LdProof.getFromJsonLDObject(vcJsonLdObject);
        if (Objects.isNull(ldProofWithJWS)) {
            CredVerifierLogger.error("Proof document is not available in the received credentials");
            throw new ProofDocumentNotFoundException("Proof document is not available in the received credentials");
        }

        String ldProofTerm = ldProofWithJWS.getType();
        if (!CredentialVerifierConstants.SIGNATURE_SUITE_TERM.equals(ldProofTerm)) {
            CredVerifierLogger.error("Proof Type available in received credentials is not matching " +
                            " with supported proof terms. Recevied Type: {}", ldProofTerm);
            throw new ProofTypeNotSupportedException("Proof Type available in received credentials is not matching with supported proof terms");
        }

		try {
            URDNA2015Canonicalizer canonicalizer =	new URDNA2015Canonicalizer();
            byte[] canonicalHashBytes = canonicalizer.canonicalize(ldProofWithJWS, vcJsonLdObject);
            CredVerifierLogger.info("Completed Canonicalization for the received credentials");
            String signJWS = ldProofWithJWS.getJws();
            JWSObject jwsObject = JWSObject.parse(signJWS);
            byte[] vcSignBytes = jwsObject.getSignature().decode();
            URI publicKeyJsonUri = ldProofWithJWS.getVerificationMethod();
            PublicKey publicKeyObj = getPublicKeyFromVerificationMethod(publicKeyJsonUri);
            if (Objects.isNull(publicKeyObj)) {
                CredVerifierLogger.error("Public key object is null, returning false");
                throw new PublicKeyNotFoundException("Public key object is null");
            }
            CredVerifierLogger.info("Completed downloading public key from the issuer domain and constructed public key object");
            byte[] actualData = JWSUtil.getJwsSigningInput(jwsObject.getHeader(), canonicalHashBytes);
            String jwsHeader = jwsObject.getHeader().getAlgorithm().getName();
            CredVerifierLogger.info("Performing signature verification after downloading the public key");
            SignatureVerifier signatureVerifier = SIGNATURE_VERIFIER.get(jwsHeader);
            return signatureVerifier.verify(publicKeyObj,actualData, vcSignBytes);
        } catch (PublicKeyNotFoundException | SignatureVerificationException ex){
            throw ex;
        }
        catch (Exception e) {
            CredVerifierLogger.error("Error while doing verification of verifiable credential", e);
            throw new UnknownException("Error while doing verification of verifiable credential");
        }
    }

    private PublicKey getPublicKeyFromVerificationMethod(URI publicKeyJsonUri){

        try {
            RestTemplate restTemplate = new RestTemplate();
            ObjectNode response = restTemplate.exchange(publicKeyJsonUri, HttpMethod.GET, null, ObjectNode.class).getBody();
            String publicKeyPem = response.get(CredentialVerifierConstants.PUBLIC_KEY_PEM).asText();
            CredVerifierLogger.info("public key download completed");
            StringReader strReader = new StringReader(publicKeyPem);
            PemReader pemReader = new PemReader(strReader);
            PemObject pemObject = pemReader.readPemObject();
            byte[] pubKeyBytes = pemObject.getContent();
            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(pubKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePublic(pubKeySpec);
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException | ResourceAccessException e) {
            CredVerifierLogger.error("Error Generating public key object", e);
        }
		return null;
    }

    private ConfigurableDocumentLoader getConfigurableDocumentLoader() {

        CredVerifierLogger.info("Creating ConfigurableDocumentLoader Object with configured URLs");
        RestTemplate restTemplate = new RestTemplate();
        ConfigurableDocumentLoader confDocumentLoader = new ConfigurableDocumentLoader();
        if(Objects.isNull(vcContextUrlMap)){
			CredVerifierLogger.warn("CredentialsVerifier::getConfigurableDocumentLoader " +
                    "Warning - Verifiable Credential Context URL Map not configured");
			confDocumentLoader = new ConfigurableDocumentLoader();
			confDocumentLoader.setEnableHttps(true);
			confDocumentLoader.setEnableHttp(true);
			confDocumentLoader.setEnableFile(false);
		} else {
			Map<URI, JsonDocument> jsonDocumentCacheMap = new HashMap<URI, JsonDocument> ();
			vcContextUrlMap.keySet().stream().forEach(contextUrl -> {
				String localConfigUri = vcContextUrlMap.get(contextUrl);
                String vcContextJson = restTemplate.getForObject(configServerFileStorageUrl + localConfigUri, String.class);
				try {
                    JsonDocument jsonDocument = JsonDocument.of(new StringReader(vcContextJson));
					jsonDocumentCacheMap.put(new URI(contextUrl), jsonDocument);
				} catch (URISyntaxException | JsonLdError e) {
                    CredVerifierLogger.error("Error downloading Context files from config service.localConfigUri: " + localConfigUri +
                            "contextUrl: " + contextUrl, e);
                    throw new UnknownException("Error downloading Context files from config service");
				}
			});
			confDocumentLoader = new ConfigurableDocumentLoader(jsonDocumentCacheMap);
			confDocumentLoader.setEnableHttps(false);
			confDocumentLoader.setEnableHttp(false);
			confDocumentLoader.setEnableFile(false);
			CredVerifierLogger.info( "CredentialsVerifier::getConfigurableDocumentLoader" +
					"Added cache for the list of configured URL Map: " + jsonDocumentCacheMap.keySet().toString());
		}
        return confDocumentLoader;
    }
}
