package com.example.fido2.endpoint.fido;

import lombok.Data;

@Data
public class Fido2AuthenticationRequest {

    protected String id;
    protected String rawId;
    protected String type;
    protected Response response;

    @Data
    public static class Response {
        String authenticatorData;
        String clientDataJSON;
        String signature;
        String userHandle;
    }
}
