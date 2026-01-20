package com.example.authservice.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class RegisterRequest {

    @NotBlank(message = "Username is required")
    private String username;

    @NotBlank(message = "Email is required")
    @Email(message = "Email should be in a valid format")
    private String email;

    @NotBlank(message = "Password is required")
    @Size(min = 4, max = 16, message = "Password length should be between 4 and 16 characters")
    private String password;
}