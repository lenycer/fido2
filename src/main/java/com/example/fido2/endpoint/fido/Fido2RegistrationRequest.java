package com.example.fido2.endpoint.fido;

import lombok.Data;

@Data
public class Fido2RegistrationRequest {

    protected String id;
    protected String rawId;
    protected String type;
    protected Response response;

    @Data
    public static class Response {
        String attestationObject;
        String clientDataJSON;
    }
}
