package com.example.fido2.component.challenge;

import javax.servlet.http.HttpServletRequest;

public interface ChallengeComponent {
    public String getType();
    public FidoChallenge generate(String username);
}
