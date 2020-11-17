package com.example.fido2.component.challenge;

import com.webauthn4j.data.client.Origin;

public interface FidoChallenge {
    public String getChallenge();
    public String getRpId();
    public Origin getOrigin();
}
