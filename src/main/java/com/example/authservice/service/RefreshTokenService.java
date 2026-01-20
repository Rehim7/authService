package com.example.authservice.service;
import com.example.authservice.model.RefreshToken;
import com.example.authservice.model.TokenRefreshException;
import com.example.authservice.model.UserCredential;
import com.example.authservice.repository.RefreshTokenRepository;
import com.example.authservice.repository.UserCredentialRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.security.auth.Refreshable;
import java.sql.Ref;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Service
public class RefreshTokenService {
    @Value("${security.jwt.refresh-token.token-expiration}")
    private Long expiration;

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserCredentialRepository userRepository;
    public RefreshTokenService(RefreshTokenRepository refreshTokenRepository, UserCredentialRepository userRepository) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.userRepository = userRepository;
    }


    public RefreshToken createToken(String  email) {
        var user = userRepository.findByEmail(email).orElseThrow();
        refreshTokenRepository.findByUserCredential(user).ifPresent(refreshTokenRepository::delete);

        RefreshToken refreshToken = RefreshToken.builder()
                .userCredential(user)
                .token(UUID.randomUUID().toString())
                .expiryDate(Instant.now().plusMillis(expiration))
                .build();
        return  refreshTokenRepository.save(refreshToken);
    }

    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }

    public RefreshToken refreshTokenExpiration(RefreshToken refreshToken) {
        if (refreshToken.getExpiryDate().compareTo(Instant.now()) < 0) {
            refreshTokenRepository.delete(refreshToken);
            throw new TokenRefreshException("Refresh token's time expired.Please log in again");
        }
        return refreshToken;
    }

}



