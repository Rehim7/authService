package com.example.authservice.dto;

import lombok.Data;

import java.util.List;

@Data
public class AuthResponse {
    private String accessToken;
    private String token;
    private List<String> roles;

    public AuthResponse(String accessToken, String token, List<String> roles) {
        this.accessToken = accessToken;
        this.token = token;
        this.roles = roles;
    }
}
