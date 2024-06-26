package io.mosip.vercred;

import java.io.IOException;
import java.io.StringReader;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import com.apicatalog.jsonld.JsonLdError;
import com.apicatalog.jsonld.document.JsonDocument;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.JWSObject;

import io.mosip.vercred.exception.ProofDocumentNotFoundException;
import io.mosip.vercred.exception.ProofTypeNotFoundException;
import io.mosip.vercred.exception.PubicKeyNotFoundException;
import io.mosip.vercred.exception.UnknownException;
import io.mosip.vercred.util.Utils;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;

import foundation.identity.jsonld.ConfigurableDocumentLoader;
import foundation.identity.jsonld.JsonLDException;
import foundation.identity.jsonld.JsonLDObject;
import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.canonicalizer.URDNA2015Canonicalizer;
import info.weboftrust.ldsignatures.util.JWSUtil;
import io.mosip.vercred.contant.CredentialVerifierConstants;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

public class CredentialsVerifier {

    Logger CredVerifierLogger = LoggerFactory.getLogger(CredentialsVerifier.class);

    @Value("#{${mosip.vercred.verify.context.url.map}}")
    private Map<String, String> vcContextUrlMap;

    @Value("${mosip.config.server.file.storage.uri:}")
    private String configServerFileStorageUrl;

    private Utils utils = new Utils();

    public boolean verifyCredentials(String credentials) throws JsonLDException, GeneralSecurityException, IOException, ParseException {
        testNetworkCall("https://www.google.com/");

        ConfigurableDocumentLoader confDocumentLoader = getConfigurableDocumentLoader();

        System.out.println("About to create vcJsonLdObject.");
        JsonLDObject vcJsonLdObject = JsonLDObject.fromJson(credentials);
        vcJsonLdObject.setDocumentLoader(confDocumentLoader);
        System.out.println("created vcJsonLdObject.");

        System.out.println("About to create ldProofWithJWS.");
        LdProof ldProofWithJWS = LdProof.getFromJsonLDObject(vcJsonLdObject);
        if (Objects.isNull(ldProofWithJWS)) {
            System.out.println("Proof document is not available in the received credentials.");
            return false;
        }
        System.out.println("created ldProofWithJWS.");

        System.out.println("About to create ldProofTerm.");
        String ldProofTerm = ldProofWithJWS.getType();
        System.out.println("created ldProofTerm.");
        if (!CredentialVerifierConstants.SIGNATURE_SUITE_TERM.equals(ldProofTerm)) {
            CredVerifierLogger.error("Proof Type available in received credentials is not matching " +
                    " with supported proof terms. Recevied Type: {}", ldProofTerm);
            return false;
        }

        try {
            System.out.println("About to create URDNA2015Canonicalizer.");
            URDNA2015Canonicalizer canonicalizer = new URDNA2015Canonicalizer();
            System.out.println("created URDNA2015Canonicalizer.");
            System.out.println("calling canonicalize.");
            byte[] canonicalHashBytes = canonicalizer.canonicalize(ldProofWithJWS, vcJsonLdObject);
            CredVerifierLogger.info("Completed Canonicalization for the received credentials.");
            String signJWS = ldProofWithJWS.getJws();
            JWSObject jwsObject = JWSObject.parse(signJWS);
            byte[] vcSignBytes = jwsObject.getSignature().decode();
            URI publicKeyJsonUri = ldProofWithJWS.getVerificationMethod();
            PublicKey publicKeyObj = getPublicKeyFromVerificationMethod(publicKeyJsonUri);
            if (Objects.isNull(publicKeyObj)) {
                CredVerifierLogger.error("Public key object is null, returning false.");
                return false;
            }
            CredVerifierLogger.info("Completed downloading public key from the issuer domain and constructed public key object.");
            byte[] actualData = JWSUtil.getJwsSigningInput(jwsObject.getHeader(), canonicalHashBytes);
            String jwsHeader = jwsObject.getHeader().getAlgorithm().getName();
            CredVerifierLogger.info("Performing signature verification after downloading the public key.");
            return verifyCredentialSignature(jwsHeader, publicKeyObj, actualData, vcSignBytes);
        } catch (IOException | GeneralSecurityException | JsonLDException | ParseException e) {
            e.printStackTrace();
            CredVerifierLogger.error("Error in doing verifiable credential verification process.", e);
        }
        return false;
    }

    private void testNetworkCall(String url) {
        try {
            CredVerifierLogger.info("Test n/w call start " + url);
            OkHttpClient okHttpClient = new OkHttpClient.Builder().build();
            Request request = new Request.Builder()
                    .url(url)
                    .get()
                    .build();
            Response response = okHttpClient.newCall(request).execute();
            CredVerifierLogger.info("Test n/w call body " + response.body().toString());
        } catch (Exception exception) {
            CredVerifierLogger.error("Test n/w call failed exception " + exception);
            exception.printStackTrace();
            CredVerifierLogger.error("Test n/w call failed");
        }
    }

    public boolean verifyPrintCredentials(String credentials) throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException, KeyManagementException {
        CredVerifierLogger.info("Received Credentials Verification - Start.");
        ConfigurableDocumentLoader confDocumentLoader = getConfigurableDocumentLoader();

        JsonLDObject vcJsonLdObject = JsonLDObject.fromJson(credentials);
        vcJsonLdObject.setDocumentLoader(confDocumentLoader);

        LdProof ldProofWithJWS = LdProof.getFromJsonLDObject(vcJsonLdObject);
        if (Objects.isNull(ldProofWithJWS)) {
            CredVerifierLogger.error("Proof document is not available in the received credentials.");
            throw new ProofDocumentNotFoundException("Proof document is not available in the received credentials.");
        }

        String ldProofTerm = ldProofWithJWS.getType();
        if (!CredentialVerifierConstants.SIGNATURE_SUITE_TERM.equals(ldProofTerm)) {
            CredVerifierLogger.error("Proof Type available in received credentials is not matching " +
                    " with supported proof terms. Recevied Type: {}", ldProofTerm);
            throw new ProofTypeNotFoundException("Proof Type available in received credentials is not matching with supported proof terms.");
        }

        try {

            URDNA2015Canonicalizer canonicalizer = new URDNA2015Canonicalizer();
            byte[] canonicalHashBytes = canonicalizer.canonicalize(ldProofWithJWS, vcJsonLdObject);
            CredVerifierLogger.info("Completed Canonicalization for the received credentials.");
            String signJWS = ldProofWithJWS.getJws();
            JWSObject jwsObject = JWSObject.parse(signJWS);
            byte[] vcSignBytes = jwsObject.getSignature().decode();
            URI publicKeyJsonUri = ldProofWithJWS.getVerificationMethod();
            PublicKey publicKeyObj = getPublicKeyFromVerificationMethod(publicKeyJsonUri);
            if (Objects.isNull(publicKeyObj)) {
                CredVerifierLogger.error("Public key object is null, returning false.");
                throw new PubicKeyNotFoundException("Public key object is null.");
            }
            CredVerifierLogger.info("Completed downloading public key from the issuer domain and constructed public key object.");
            byte[] actualData = JWSUtil.getJwsSigningInput(jwsObject.getHeader(), canonicalHashBytes);
            String jwsHeader = jwsObject.getHeader().getAlgorithm().getName();
            CredVerifierLogger.info("Performing signature verification after downloading the public key.");
            return verifyCredentialSignature(jwsHeader, publicKeyObj, actualData, vcSignBytes);
        } catch (IOException | GeneralSecurityException | JsonLDException | ParseException e) {
            CredVerifierLogger.error("Error in doing verifiable credential verification process.", e);
            throw new UnknownException("Error in doing verifiable credential verification process.");
        }
    }

    private PublicKey getPublicKeyFromVerificationMethod(URI publicKeyJsonUri) throws CertificateException, KeyStoreException, KeyManagementException {

        try {
            OkHttpClient okHttpClient = getHttpClient().newBuilder().build();
            Request request = new Request.Builder()
                    .url(publicKeyJsonUri.toURL())
                    .get()
                    .build();
            Response response = okHttpClient.newCall(request).execute();
            ObjectNode responseObjectNode = null;
            if (response.body() != null) {
                String responseBody = response.body().string();

                // Convert JSON string to ObjectNode
                ObjectMapper objectMapper = new ObjectMapper();
                JsonNode jsonNode = objectMapper.readTree(responseBody);
                if (jsonNode.isObject()) {
                    responseObjectNode = (ObjectNode) jsonNode;
                }
                String publicKeyPem = responseObjectNode.get(CredentialVerifierConstants.PUBLIC_KEY_PEM).asText();
                StringReader strReader = new StringReader(publicKeyPem);
                PemReader pemReader = new PemReader(strReader);
                PemObject pemObject = pemReader.readPemObject();
                byte[] pubKeyBytes = pemObject.getContent();
                X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(pubKeyBytes);
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                return keyFactory.generatePublic(pubKeySpec);
            }
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            CredVerifierLogger.error("Error Generating public key object." + e);
        }
        return null;
    }

    private boolean verifyCredentialSignature(String algorithm, PublicKey publicKey, byte[] actualData, byte[] signature) {

        if (algorithm.equals(CredentialVerifierConstants.JWS_RS256_SIGN_ALGO_CONST)) {
            try {
                CredVerifierLogger.info("Validating signature using RS256 algorithm.");
                Signature rsSignature = Signature.getInstance(CredentialVerifierConstants.RS256_ALGORITHM);
                rsSignature.initVerify(publicKey);
                rsSignature.update(actualData);
                return rsSignature.verify(signature);
            } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
                CredVerifierLogger.error("Error in Verifying credentials(RS256).", e);
            }
        }
        try {
            CredVerifierLogger.info("Validating signature using PS256 algorithm.");
            Signature psSignature = getPS256Signature();

            PSSParameterSpec pssParamSpec = new PSSParameterSpec(CredentialVerifierConstants.PSS_PARAM_SHA_256, CredentialVerifierConstants.PSS_PARAM_MGF1,
                    MGF1ParameterSpec.SHA256, CredentialVerifierConstants.PSS_PARAM_SALT_LEN, CredentialVerifierConstants.PSS_PARAM_TF);
            psSignature.setParameter(pssParamSpec);

            psSignature.initVerify(publicKey);
            psSignature.update(actualData);
            return psSignature.verify(signature);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException | InvalidAlgorithmParameterException e) {
            CredVerifierLogger.error("Error in Verifying credentials(PS256).", e);
        }
        return false;
    }

    private Signature getPS256Signature() throws NoSuchAlgorithmException {
        if(utils.isAndroid()){
            return Signature.getInstance(CredentialVerifierConstants.PS256_ALGORITHM_ANDROID);
        }
        return Signature.getInstance(CredentialVerifierConstants.PS256_ALGORITHM);
        /*try {
            return Signature.getInstance(CredentialVerifierConstants.PS256_ALGORITHM);
        } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
            CredVerifierLogger.warn("Algorithm - " + CredentialVerifierConstants.PS256_ALGORITHM + " is not supported in the current environment, trying out algorithm - " + CredentialVerifierConstants.PS256_ALGORITHM_ANDROID);
            return Signature.getInstance(CredentialVerifierConstants.PS256_ALGORITHM_ANDROID);
        }*/
    }

    private ConfigurableDocumentLoader getConfigurableDocumentLoader() throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException, KeyManagementException {
        OkHttpClient okHttpClient = getHttpClient();

        ConfigurableDocumentLoader confDocumentLoader;
        if (Objects.isNull(vcContextUrlMap)) {
            CredVerifierLogger.warn("CredentialsVerifier::getConfigurableDocumentLoader " +
                    "Warning - Verifiable Credential Context URL Map not configured.");
            confDocumentLoader = new ConfigurableDocumentLoader();
            confDocumentLoader.setEnableHttps(true);
            confDocumentLoader.setEnableHttp(true);
            confDocumentLoader.setEnableFile(false);
        } else {
            Map<URI, JsonDocument> jsonDocumentCacheMap = new HashMap<URI, JsonDocument>();
            vcContextUrlMap.keySet().stream().forEach(contextUrl -> {
                String localConfigUri = vcContextUrlMap.get(contextUrl);
                Request request = new Request.Builder()
                        .url((configServerFileStorageUrl + localConfigUri))
                        .get()
                        .build();
                String vcContextJson = null;
                try {
                    Response response = okHttpClient.newCall(request).execute();
                    if (response.body() != null) {
                        vcContextJson = Arrays.toString(response.body().byteStream().readAllBytes());
                    }
                } catch (IOException ioException) {
                    CredVerifierLogger.error("Error downloading Context files from config service.localConfigUri: " + localConfigUri +
                            "contextUrl: " + contextUrl + " " + ioException);
                }
                try {
                    JsonDocument jsonDocument = JsonDocument.of(new StringReader(vcContextJson));
                    jsonDocumentCacheMap.put(new URI(contextUrl), jsonDocument);
                } catch (URISyntaxException | JsonLdError e) {
                    CredVerifierLogger.error("Error downloading Context files from config service.localConfigUri: " + localConfigUri +
                            "contextUrl: " + contextUrl + " " + e);
                }
            });
            confDocumentLoader = new ConfigurableDocumentLoader(jsonDocumentCacheMap);
            confDocumentLoader.setEnableHttps(false);
            confDocumentLoader.setEnableHttp(false);
            confDocumentLoader.setEnableFile(false);
            CredVerifierLogger.info("CredentialsVerifier::getConfigurableDocumentLoader" +
                    "Added cache for the list of configured URL Map: " + jsonDocumentCacheMap.keySet().toString());
        }
        return confDocumentLoader;
    }

    private OkHttpClient getHttpClient() throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException, KeyManagementException {
        OkHttpClient.Builder builder = new OkHttpClient.Builder();

        if (utils.isAndroid()/* && Build.VERSION.SDK_INT <= 25*/) {
            TrustManagerFactory tmf = new MyTrustManagerFactory().getTrustManagerFactory();
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, tmf.getTrustManagers(), null);
            builder.sslSocketFactory(context.getSocketFactory(), (X509TrustManager) tmf.getTrustManagers()[0]);
        }
        return builder.build();
    }
}
