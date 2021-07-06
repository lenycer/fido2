package com.example.fido2.component.server;

import com.example.fido2.component.cache.SimpleCache;
import com.example.fido2.component.challenge.FidoChallenge;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.util.Base64Util;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

@Component
public class ServerPropertyComponent {

    @Autowired
    SimpleCache simpleCache;

    public ServerProperty getServerProperty(String challengeId) {
        // Server properties
        FidoChallenge fidoChallenge = (FidoChallenge) simpleCache.getChallenge(challengeId);
        Origin origin = fidoChallenge.getOrigin();
        String rpId = fidoChallenge.getRpId();
//        Origin origin = new Origin("http://localhost:8080");
//        String rpId = "localhost";
        Challenge challenge = new Challenge() {
            @Override
            public byte[] getValue() {
                return Base64Util.decode(fidoChallenge.getChallenge().replaceAll("-", "+").replaceAll("_", "/"));
            }
        };
        byte[] tokenBindingId = null /* set tokenBindingId */;
        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, tokenBindingId);

        return serverProperty;
    }
}
