package com.example.fido2.component.challenge;

import com.example.fido2.component.cache.SimpleCache;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.util.Base64Util;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.util.List;

@Slf4j
@Component
public class AuthenticationChallengeComponent implements ChallengeComponent {

    @Autowired
    SimpleCache simpleCache;

    @Override
    public String getType() {
        return "auth";
    }

    @Override
    public FidoChallenge generate(String username) {
        AuthenticationFidoChallenge fidoChallenge = new AuthenticationFidoChallenge(username, simpleCache);
        log.info("fido auth challenge : {}", fidoChallenge);
        simpleCache.putChallenge(fidoChallenge.getChallenge(), fidoChallenge);
        return fidoChallenge;
    }

    @Data
    public static class AuthenticationFidoChallenge implements FidoChallenge {
        private String challenge;
        private RegistrationChallengeComponent.RegistrationFidoChallenge.RelayParty rp;
        @JsonIgnore
        private Origin origin;
        @JsonIgnore
        private String username;
        private List<AllowCredentials> allowCredentials;

        public AuthenticationFidoChallenge(String username, SimpleCache simpleCache) {
            this.challenge = Base64Util.encodeToString(new DefaultChallenge().getValue());
//            String url = String.format("%s://%s:%s", request.getScheme(), request.getServerName(), request.getServerPort());
//            this.origin = new Origin(url);
//            this.rpId = origin.getHost();
            //TODO Authorization Basic 정보 기반 rp, origin 정보 set
            String rpUrl = "http://localhost:8080";
            this.origin = new Origin(rpUrl);

            RegistrationChallengeComponent.RegistrationFidoChallenge.RelayParty rp = new RegistrationChallengeComponent.RegistrationFidoChallenge.RelayParty();
            rp.setId(origin.getHost());
            rp.setName("fido test");
            this.rp = rp;

            this.allowCredentials = simpleCache.getCredentialIds(username);
            this.username = username;
        }

        @Override
        public String getRpId() {
            return this.rp.getId();
        }

        @Data
        @AllArgsConstructor
        public static class AllowCredentials {
            String id;
            String type;
            List<String> transports;
        }
    }
}
