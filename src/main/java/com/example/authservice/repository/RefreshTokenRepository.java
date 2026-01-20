package com.example.authservice.repository;

import com.example.authservice.model.RefreshToken;
import com.example.authservice.model.UserCredential;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByUserCredential(UserCredential userCredential);

    Optional<RefreshToken> findByToken(String token);
}
