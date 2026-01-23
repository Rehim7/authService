package com.example.authservice.controller;

import com.example.authservice.dto.AuthRequest;
import com.example.authservice.dto.AuthResponse;
import com.example.authservice.dto.RefreshTokenRequest;
import com.example.authservice.dto.RegisterRequest;
import com.example.authservice.model.RefreshToken;
import com.example.authservice.model.TokenRefreshException;
import com.example.authservice.repository.UserCredentialRepository;
import com.example.authservice.service.AuthService;
import com.example.authservice.service.JwtService;
import com.example.authservice.service.RefreshTokenService;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/hotelReservationSystem/auth")
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);

    private final AuthService authService;

    private final RefreshTokenService refreshTokenService;

    private final JwtService jwtService;

    private final UserCredentialRepository repository;


    public AuthController(AuthService authService, RefreshTokenService refreshTokenService, JwtService jwtService,
            UserCredentialRepository repository) {
        this.authService = authService;
        this.refreshTokenService = refreshTokenService;
        this.jwtService = jwtService;
        this.repository = repository;
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest request) {
        if (repository.findByEmail(request.getEmail()).isPresent()) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body("Error: Email is already in use!");
        }

        return ResponseEntity.ok(authService.register(request));
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody AuthRequest authRequest) {
        try {
            return ResponseEntity.ok(authService.login(authRequest));

        } catch (AuthenticationException e) {
            log.warn("Authentication failed for user {}: {}", authRequest.getEmail(), e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Giriş qadağandır! Məlumatlar səhvdir.");
        }
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<?> refreshToken(@RequestBody RefreshTokenRequest request) {
        return refreshTokenService.findByToken(request.getToken())
                .map(refreshTokenService::refreshTokenExpiration)
                .map(RefreshToken::getUserCredential)
                .map(user -> {
                    String accessToken = jwtService.generateToken(user);
                    List<String> roles = user.getAuthorities().stream()
                            .map(GrantedAuthority::getAuthority)
                            .collect(Collectors.toList());
                    return ResponseEntity.ok(new AuthResponse(accessToken, request.getToken(), roles));
                })
                .orElseThrow(() -> new TokenRefreshException("Refresh token is not in database!"));
    }

    @GetMapping("/validate")
    public ResponseEntity<String> validate(@RequestParam("token") String token) {
        try {
            // validateToken yerinə yeni yazdığımız metodu çağırırıq
            String identity = jwtService.validateToken(token);
            return ResponseEntity.ok(identity);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }
}