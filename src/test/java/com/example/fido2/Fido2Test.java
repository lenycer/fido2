package com.example.fido2;

import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.authenticator.AuthenticatorImpl;
import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.data.*;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.util.Base64UrlUtil;
import com.webauthn4j.util.Base64Util;
import com.webauthn4j.validator.exception.ValidationException;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.springframework.util.Base64Utils;

import java.util.Collections;
import java.util.List;
import java.util.Set;

@Slf4j
public class Fido2Test {

    @Test
    public void fido2Test() {

        String attestation = "o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZyZjc2lnWEgwRgIhAOJ6zXa0SqamQnrTm5AmxilbSMGvUp-qc9d0wMCSap_0AiEAwYfh-u-oFzdbm9Bbor-tikDVDlDAQGEkPtyQGUue7IVoYXV0aERhdGFYuHSm6pITyZwvdLIkkrMgz0AmKpTBqVCgOX8pJQtghB7wRV-WNg6tzgACNbzGCmSLCyXx8FUDADQBYmlXhRezOvIH4HAmVj2Cx8djSuMCEMc-QEqbcs1k3O_5BPCOMqq3K9E0ijm-c85h60EBpQECAyYgASFYIHZC3eEEUmDRY6B3NAvD_ivzNn2dVHEFqdj9IYtj0xtaIlggONz6qB3Cm7NzsZM-pfG2-aq1JPvbbRox25zL9pfwjE0";
        String clientData = "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiTXN1NUF1dWY5TzR0QVZPalE2aTdmSmk5bnpzX1lQMlBsYWJibjMzbVpWdyIsIm9yaWdpbiI6Imh0dHBzOi8vd2ViYXV0aG4uaW8iLCJjcm9zc09yaWdpbiI6ZmFsc2V9";
        String challengeStr = "Msu5Auuf9O4tAVOjQ6i7fJi9nzs/YP2Plabbn33mZVw=";

        Authenticator authenticator = registration(attestation, clientData, challengeStr);

        String authChallenge = "-BygilaLNV012qTgyIkQ4ftLr7ePJ83Rd_SAtrt8G28";

        byte[] userHandle = Base64UrlUtil.decode("gOUJAAAAAAAAAA");
        byte[] authenticatorData = Base64UrlUtil.decode("dKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvAFX5ZSxw");
        byte[] clientDataJSON = Base64UrlUtil.decode("eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiLUJ5Z2lsYUxOVjAxMnFUZ3lJa1E0ZnRMcjdlUEo4M1JkX1NBdHJ0OEcyOCIsIm9yaWdpbiI6Imh0dHBzOi8vd2ViYXV0aG4uaW8iLCJjcm9zc09yaWdpbiI6ZmFsc2V9");
        byte[] signature = Base64UrlUtil.decode("MEQCIGib8XFQubUTxip8iFFcrMFwjuZ0iFyhen_cmlvaQXJOAiBeSSoVVaTK7cDctGNOROtC81FSheWg_5QaVqmqFsBEFg");
        authentication(authenticator, userHandle, authenticatorData, clientDataJSON, signature, authChallenge);
    }

    private Authenticator registration(String attestation, String clientData, String challengeStr) {
        byte[] attestationObject = Base64UrlUtil.decode(attestation);
        byte[] clientDataJSON = Base64UrlUtil.decode(clientData);
        String clientExtensionJSON = null;  /* set clientExtensionJSON */;
        Set<String> transports = null /* set transports */;

        // Server properties
        Origin origin = new Origin("https://webauthn.io");
        String rpId = "webauthn.io";
        Challenge challenge = new Challenge() {
            @Override
            public byte[] getValue() {
                return Base64Util.decode(challengeStr);
            }
        };
        byte[] tokenBindingId = null /* set tokenBindingId */;
        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, tokenBindingId);

        // expectations
        boolean userVerificationRequired = false;
        boolean userPresenceRequired = true;
        List<String> expectedExtensionIds = Collections.emptyList();

        RegistrationRequest registrationRequest = new RegistrationRequest(attestationObject, clientDataJSON, clientExtensionJSON, transports);
        RegistrationParameters registrationParameters = new RegistrationParameters(serverProperty, userVerificationRequired, userPresenceRequired);
        RegistrationData registrationData;

        WebAuthnManager webAuthnManager = WebAuthnManager.createNonStrictWebAuthnManager();

        try{
            registrationData = webAuthnManager.parse(registrationRequest);
        }
        catch (DataConversionException e){
            // If you would like to handle WebAuthn data structure parse error, please catch DataConversionException
            throw e;
        }
        try{
            webAuthnManager.validate(registrationData, registrationParameters);
        }
        catch (ValidationException e){
            // If you would like to handle WebAuthn data validation error, please catch ValidationException
            throw e;
        }

        // please persist Authenticator object, which will be used in the authentication process.
        Authenticator authenticator =
                new AuthenticatorImpl( // You may create your own Authenticator implementation to save friendly authenticator name
                        registrationData.getAttestationObject().getAuthenticatorData().getAttestedCredentialData(),
                        registrationData.getAttestationObject().getAttestationStatement(),
                        registrationData.getAttestationObject().getAuthenticatorData().getSignCount()
                );
        //save(authenticator); // please persist authenticator in your manner
        log.info("aaguid : {}", authenticator.getAttestedCredentialData().getAaguid());
        log.info("credential id : {}", Base64Util.encodeToString(authenticator.getAttestedCredentialData().getCredentialId()));
        log.info("attestation format : {}", authenticator.getAttestationStatement().getFormat());
        log.info("attestation : {}", authenticator.getAttestationStatement().toString());
        log.info("attestation : {}", authenticator.getAttestedCredentialData().getCOSEKey().toString());

        return authenticator;
    }

    private void authentication(Authenticator authenticator, byte[] userHandle, byte[] authenticatorData, byte[] clientDataJSON, byte[] signature, String authChallenge) {
        // Client properties
//        byte[] credentialId = null /* set credentialId */;
//        byte[] userHandle = null /* set userHandle */;
//        byte[] authenticatorData = null /* set authenticatorData */;
//        byte[] clientDataJSON = null /* set clientDataJSON */;
        String clientExtensionJSON = null /* set clientExtensionJSON */;
//        byte[] signature = null /* set signature */;

        // Server properties
        Origin origin = new Origin("https://webauthn.io");
        String rpId = "webauthn.io";
        Challenge challenge = new Challenge() {
            @Override
            public byte[] getValue() {
                return Base64UrlUtil.decode(authChallenge);
            }
        };
        byte[] tokenBindingId = null /* set tokenBindingId */;
        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, tokenBindingId);

        // expectations
        boolean userVerificationRequired = true;
        boolean userPresenceRequired = true;
        List<String> expectedExtensionIds = Collections.emptyList();

//        Authenticator authenticator = load(credentialId); // please load authenticator object persisted in the registration process in your manner

        AuthenticationRequest authenticationRequest =
                new AuthenticationRequest(
                        authenticator.getAttestedCredentialData().getCredentialId(),
                        userHandle,
                        authenticatorData,
                        clientDataJSON,
                        clientExtensionJSON,
                        signature
                );
        AuthenticationParameters authenticationParameters =
                new AuthenticationParameters(
                        serverProperty,
                        authenticator,
                        userVerificationRequired,
                        userPresenceRequired
                );

        WebAuthnManager webAuthnManager = WebAuthnManager.createNonStrictWebAuthnManager();

        AuthenticationData authenticationData;

        try{
            authenticationData = webAuthnManager.parse(authenticationRequest);
        }
        catch (DataConversionException e){
            // If you would like to handle WebAuthn data structure parse error, please catch DataConversionException
            throw e;
        }
        try{
            AuthenticationData validate = webAuthnManager.validate(authenticationData, authenticationParameters);
            log.info("clientData credential id: {}", Base64UrlUtil.encodeToString(validate.getCredentialId()));
            log.info("clientData type: {}", validate.getCollectedClientData().getType().getValue());
            log.info("clientData challenge: {}", Base64UrlUtil.encodeToString(validate.getCollectedClientData().getChallenge().getValue()));
            log.info("clientData origin: {}", validate.getCollectedClientData().getOrigin().toString());

        }
        catch (ValidationException e){
            // If you would like to handle WebAuthn data validation error, please catch ValidationException
            throw e;
        }
        // please update the counter of the authenticator record
//        updateCounter(
//                authenticationData.getCredentialId(),
//                authenticationData.getAuthenticatorData().getSignCount()
//        );
    }
}
