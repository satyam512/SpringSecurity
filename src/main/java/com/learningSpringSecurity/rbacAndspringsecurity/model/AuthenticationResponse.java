package com.learningSpringSecurity.rbacAndspringsecurity.model;

public class AuthenticationResponse {
    private final String Jwt;

    public AuthenticationResponse(String jwt) {
        Jwt = jwt;
    }

    public String getJwt() {
        return Jwt;
    }
}
