package com.example.fido2.component.cache;

import com.example.fido2.component.challenge.AuthenticationChallengeComponent;
import com.example.fido2.component.challenge.FidoChallenge;
import com.webauthn4j.authenticator.Authenticator;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
@Component
public class SimpleCache {
    private ConcurrentHashMap<String, FidoChallenge> challengeCache = new ConcurrentHashMap<>();

    public void putChallenge(String challengeId, FidoChallenge challenge) {
        challengeCache.put(challengeId, challenge);
    }

    public FidoChallenge getChallenge(String challengeId) {
        log.info("challenge get : {}", challengeCache.get(challengeId));

        return challengeCache.get(challengeId);
    }

    private ConcurrentHashMap<String, List<AuthenticationChallengeComponent.AuthenticationFidoChallenge.AllowCredentials>> credentailIdsCache = new ConcurrentHashMap<>();

    public void putCredentialIds(String username, AuthenticationChallengeComponent.AuthenticationFidoChallenge.AllowCredentials credentailId) {
        if(credentailIdsCache.get(username) == null) {
            List<AuthenticationChallengeComponent.AuthenticationFidoChallenge.AllowCredentials> credentialIds = new ArrayList<>();
            credentialIds.add(credentailId);
            credentailIdsCache.put(username, credentialIds);
        } else {
            credentailIdsCache.get(username).add(credentailId);
        }
    }

    public List<AuthenticationChallengeComponent.AuthenticationFidoChallenge.AllowCredentials> getCredentialIds(String username) {
        return credentailIdsCache.get(username);
    }

    private ConcurrentHashMap<String, Authenticator> authenticatorCache = new ConcurrentHashMap<>();

    public void putAuthenticator(String credentailId, Authenticator authenticator) {
        authenticatorCache.put(credentailId, authenticator);
    }

    public Authenticator getAuthenticator(String credentailId) {
        return authenticatorCache.get(credentailId);
    }
}
