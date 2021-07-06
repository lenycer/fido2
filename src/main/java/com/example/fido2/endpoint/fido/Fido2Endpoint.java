package com.example.fido2.endpoint.fido;

import com.example.fido2.component.authentication.AuthenticationComponent;
import com.example.fido2.component.cache.SimpleCache;
import com.example.fido2.component.challenge.AuthenticationChallengeComponent;
import com.example.fido2.component.challenge.ChallengeFactory;
import com.example.fido2.component.challenge.FidoChallenge;
import com.example.fido2.component.challenge.RegistrationChallengeComponent;
import com.example.fido2.component.registration.RegistrationComponent;
import com.example.fido2.component.server.ServerPropertyComponent;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.data.AuthenticationData;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.util.Base64UrlUtil;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.util.Base64Utils;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.*;

@Slf4j
@RestController
public class Fido2Endpoint {

    @Autowired
    ServerPropertyComponent serverPropertyComponent;

    @Autowired
    RegistrationComponent registrationComponent;

    @Autowired
    AuthenticationComponent authenticationComponent;

    @Autowired
    SimpleCache simpleCache;

    @Autowired
    ChallengeFactory challengeFactory;

    @PostMapping("/challenge/{type}")
    public FidoChallenge challenge(@PathVariable String type, @RequestBody String clientCredentials) throws Exception {
        return challengeFactory.getInstance(type).generate(getUsername(clientCredentials));
    }

    @PostMapping("/registration")
    public InnerCredential registration(@RequestBody Fido2RegistrationRequest fido2RegistrationRequest) {
        log.info("{}", fido2RegistrationRequest);
        String challengeId = getChallengeId(new String(Base64Utils.decodeFromUrlSafeString(fido2RegistrationRequest.getResponse().getClientDataJSON())));
        log.info("challengeId: {}", challengeId);
        ServerProperty serverProperty = serverPropertyComponent.getServerProperty(challengeId);
        Authenticator authenticator = registrationComponent.registration(fido2RegistrationRequest, serverProperty);
        String credentialId = Base64UrlUtil.encodeToString(authenticator.getAttestedCredentialData().getCredentialId());

        AuthenticationChallengeComponent.AuthenticationFidoChallenge.AllowCredentials allowCredentials = new AuthenticationChallengeComponent.AuthenticationFidoChallenge.AllowCredentials(credentialId, "public-key", Arrays.asList("internal"));
        RegistrationChallengeComponent.RegistrationFidoChallenge fidoChallenge = (RegistrationChallengeComponent.RegistrationFidoChallenge) simpleCache.getChallenge(challengeId);
        simpleCache.putCredentialIds(fidoChallenge.getUser().getName(), allowCredentials);
        simpleCache.putAuthenticator(credentialId, authenticator);

        InnerCredential credential = new InnerCredential();
        credential.setUsername(fidoChallenge.getUser().getName());
        credential.setSite(fidoChallenge.getRpId());
        return credential;
    }

    @PostMapping("/authentication")
    public InnerCredential authentication(@RequestBody Fido2AuthenticationRequest fido2AuthenticationRequest) {
        log.info("{}", fido2AuthenticationRequest);
        String challengeId = getChallengeId(new String(Base64Utils.decodeFromUrlSafeString(fido2AuthenticationRequest.getResponse().getClientDataJSON())));
        ServerProperty serverProperty = serverPropertyComponent.getServerProperty(challengeId);
        AuthenticationData authenticationData = authenticationComponent.authentication(fido2AuthenticationRequest, serverProperty);

        AuthenticationChallengeComponent.AuthenticationFidoChallenge fidoChallenge = (AuthenticationChallengeComponent.AuthenticationFidoChallenge) simpleCache.getChallenge(challengeId);
        InnerCredential credential = new InnerCredential();
        credential.setUsername(fidoChallenge.getUsername());
        credential.setSite(fidoChallenge.getRpId());
        return credential;
    }

    private String getUsername(String clientCredentials) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        Map<String, String> userCredentials = mapper.readValue(clientCredentials, Map.class);
        String username = userCredentials.get("userId");
        if(StringUtils.isEmpty(username)) {
            String context = userCredentials.get("context");
            CredentialContext cc = mapper.readValue(context, CredentialContext.class);
            if(cc != null) {
                Optional<InnerCredential> ic = cc.getCredentials().stream().findFirst();
                username = ic.get().getUsername();
            }
        }

        return username;
    }

    private String getChallengeId(String clientJson) {
        String challengeId = null;
        ObjectMapper mapper = new ObjectMapper();
        try {
            Map<String, String> map = mapper.readValue(clientJson, Map.class);
            challengeId = map.get("challenge");
        } catch (Exception e) {
            e.printStackTrace();
        }

        return challengeId;
    }

    @Data
    public static class CredentialContext {
        private List<InnerCredential> credentials;
    }

    @Data
    public static class InnerCredential {
        private String site;
        private String username;
    }

    public static void main(String[] args) {
        String challenge = "hVVjw+RbK6nJle8DrCNymSUi/9S7H90NEuZaqBpJhVU=";
        String clientJSON = "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiaFZWanctUmJLNm5KbGU4RHJDTnltU1VpXzlTN0g5ME5FdVphcUJwSmhWVSIsIm9yaWdpbiI6Imh0dHBzOi8vd2ViYXV0aG4uaW8iLCJjcm9zc09yaWdpbiI6ZmFsc2V9";
        System.out.println(new String(Base64Utils.decodeFromUrlSafeString(clientJSON)));
        System.out.println(new String(Base64Utils.decodeFromString(clientJSON)));

        System.out.println(Base64Utils.decodeFromString(challenge));

        System.out.println("2A7-qs5kT1G0_cvcMJxGjw".replaceAll("-", "+").replaceAll("_", "/"));

    }
}
