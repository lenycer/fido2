package com.example.fido2.component.registration;

import com.example.fido2.component.challenge.RegistrationChallengeComponent;
import com.example.fido2.endpoint.fido.Fido2RegistrationRequest;
import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.authenticator.AuthenticatorImpl;
import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.data.RegistrationData;
import com.webauthn4j.data.RegistrationParameters;
import com.webauthn4j.data.RegistrationRequest;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.util.Base64UrlUtil;
import com.webauthn4j.validator.exception.ValidationException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.Set;

@Slf4j
@Component
public class NonStrictRegistrationComponent implements RegistrationComponent{

    @Override
    public Authenticator registration(Fido2RegistrationRequest fido2RegistrationRequest, ServerProperty serverProperty) {
        byte[] attestationObject = Base64UrlUtil.decode(fido2RegistrationRequest.getResponse().getAttestationObject());
        byte[] clientDataJSON = Base64UrlUtil.decode(fido2RegistrationRequest.getResponse().getClientDataJSON());
        String clientExtensionJSON = null;  /* set clientExtensionJSON */;
        Set<String> transports = null /* set transports */;

        // expectations
        boolean userVerificationRequired = false;
        boolean userPresenceRequired = true;
//        List<String> expectedExtensionIds = Collections.emptyList();

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
        log.info("credential id : {}", authenticator.getAttestedCredentialData().getCredentialId());
        log.info("attestation format : {}", authenticator.getAttestationStatement().getFormat());
        log.info("attestation : {}", authenticator.getAttestationStatement().toString());
        log.info("attestation : {}", authenticator.getAttestedCredentialData().getCOSEKey().toString());

        return authenticator;
    }
}
