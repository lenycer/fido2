package com.example.fido2.component.authentication;

import com.example.fido2.component.cache.SimpleCache;
import com.example.fido2.component.challenge.RegistrationChallengeComponent;
import com.example.fido2.endpoint.fido.Fido2AuthenticationRequest;
import com.example.fido2.endpoint.fido.Fido2RegistrationRequest;
import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.authenticator.AuthenticatorImpl;
import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.data.*;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.util.Base64UrlUtil;
import com.webauthn4j.validator.exception.ValidationException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.Collections;
import java.util.List;
import java.util.Set;

@Slf4j
@Component
public class NonStrictAuthenticationComponent implements AuthenticationComponent {

    @Autowired
    SimpleCache simpleCache;

    @Override
    public AuthenticationData authentication(Fido2AuthenticationRequest fido2AuthenticationRequest, ServerProperty serverProperty) {
        byte[] credentialId = Base64UrlUtil.decode(fido2AuthenticationRequest.getId());
        byte[] authenticatorData = Base64UrlUtil.decode(fido2AuthenticationRequest.getResponse().getAuthenticatorData());
        byte[] clientDataJSON = Base64UrlUtil.decode(fido2AuthenticationRequest.getResponse().getClientDataJSON());
        byte[] signature = Base64UrlUtil.decode(fido2AuthenticationRequest.getResponse().getSignature());
        byte[] userHandle = Base64UrlUtil.decode(fido2AuthenticationRequest.getResponse().getUserHandle());
        String clientExtensionJSON = null /* set clientExtensionJSON */;

        // expectations
        boolean userVerificationRequired = true;
        boolean userPresenceRequired = true;
        List<String> expectedExtensionIds = Collections.emptyList();

        AuthenticationRequest authenticationRequest =
                new AuthenticationRequest(
                        credentialId,
                        userHandle,
                        authenticatorData,
                        clientDataJSON,
                        clientExtensionJSON,
                        signature
                );
        AuthenticationParameters authenticationParameters =
                new AuthenticationParameters(
                        serverProperty,
                        simpleCache.getAuthenticator(fido2AuthenticationRequest.getId()),
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

        return authenticationData;
    }
}
