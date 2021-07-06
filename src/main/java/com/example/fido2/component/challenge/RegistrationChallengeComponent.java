package com.example.fido2.component.challenge;

import com.example.fido2.component.cache.SimpleCache;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.util.Base64Util;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

@Slf4j
@Component
public class RegistrationChallengeComponent implements ChallengeComponent {

    @Autowired
    SimpleCache simpleCache;

    @Override
    public String getType() {
        return "reg";
    }

    @Override
    public FidoChallenge generate(String username) {
        RegistrationFidoChallenge fidoChallenge = new RegistrationFidoChallenge(username);
        log.info("fido reg challenge : {}", fidoChallenge);
        simpleCache.putChallenge(fidoChallenge.getChallenge(), fidoChallenge);
        return fidoChallenge;
    }

    @Data
    public static class RegistrationFidoChallenge implements FidoChallenge {
        @JsonIgnore
        private Origin origin;

        public RegistrationFidoChallenge(String username) {
            this.challenge = new String(Base64.getUrlEncoder().withoutPadding().encode(new DefaultChallenge().getValue()), Charset.defaultCharset());//Base64Util.encodeToString(new DefaultChallenge().getValue());

            //TODO Authorization Basic 정보 기반 rp, origin 정보 set
            String rpUrl = "http://localhost:8080";
            this.origin = new Origin(rpUrl);

            RelayParty rp = new RelayParty();
            rp.setId(origin.getHost());
            rp.setName("fido test");
            this.rp = rp;

            FidoUser user = new FidoUser();
            user.setId(RandomStringUtils.randomAlphanumeric(10));
            user.setName(username);
            user.setDisplayName(username);
            this.user = user;

            PublicKeyCredentialParams pubKeyCredParams = new PublicKeyCredentialParams();
            pubKeyCredParams.setAlg(-7);
            pubKeyCredParams.setType("public-key");
            this.pubKeyCredParams = Arrays.asList(pubKeyCredParams);

            AuthenticatorSelection authenticatorSelection = new AuthenticatorSelection();
            authenticatorSelection.setResidentKey("discouraged");
            authenticatorSelection.setRequireResidentKey(false);
            authenticatorSelection.setAuthenticatorAttachment("platform");
            authenticatorSelection.setUserVerification("preferred");
            this.authenticatorSelection = authenticatorSelection;

            this.timeout = 6000L;
            this.attestation = "none";

//            this.userId = RandomStringUtils.randomAlphanumeric(10);
//            String url = String.format("%s://%s:%s", request.getScheme(), request.getServerName(), request.getServerPort());
//            this.origin = new Origin(url);
//            this.rpId = origin.getHost();
        }

        private String challenge;
        private RelayParty rp;
        private FidoUser user;
        private List<PublicKeyCredentialParams> pubKeyCredParams;
        private AuthenticatorSelection authenticatorSelection;
        private Long timeout;
        private String attestation;

        @Override
        public String getRpId() {
            return this.rp.getId();
        }

        @Data
        @JsonInclude(JsonInclude.Include.NON_EMPTY)
        public static class RelayParty {
            String name;
            String id;
        }

        @Data
        @JsonInclude(JsonInclude.Include.NON_EMPTY)
        public static class FidoUser {
            String id;
            String name;
            String displayName;
        }

        @Data
        @JsonInclude(JsonInclude.Include.NON_EMPTY)
        public static class PublicKeyCredentialParams {
            int alg;
            String type;
        }

        @Data
        @JsonInclude(JsonInclude.Include.NON_EMPTY)
        public static class AuthenticatorSelection {
            String residentKey;
            String authenticatorAttachment;
            String userVerification;
            boolean requireResidentKey;
        }
    }

    public static void main(String[] args) {
        for(int i=0;i<10;i++) {
//            String challenge = Base64Util.encodeToString(new DefaultChallenge().getValue());
            String challenge = new String(Base64.getUrlEncoder().withoutPadding().encode(new DefaultChallenge().getValue()), Charset.defaultCharset());
            System.out.println(challenge);

        }
    }
}
