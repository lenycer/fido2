package com.example.fido2.component.authentication;

import com.example.fido2.endpoint.fido.Fido2AuthenticationRequest;
import com.example.fido2.endpoint.fido.Fido2RegistrationRequest;
import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.data.AuthenticationData;
import com.webauthn4j.server.ServerProperty;

public interface AuthenticationComponent {
    public AuthenticationData authentication(Fido2AuthenticationRequest fido2AuthenticationRequest, ServerProperty serverProperty);
}
