package com.example.fido2.component.registration;

import com.example.fido2.endpoint.fido.Fido2RegistrationRequest;
import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.server.ServerProperty;

public interface RegistrationComponent {
    public Authenticator registration(Fido2RegistrationRequest fido2RegistrationRequest, ServerProperty serverProperty);
}
