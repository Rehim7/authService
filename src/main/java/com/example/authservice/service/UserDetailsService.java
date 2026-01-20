package com.example.authservice.service;

import com.example.authservice.repository.UserCredentialRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UserDetailsService implements org.springframework.security.core.userdetails.UserDetailsService {

    private final UserCredentialRepository userRepository;

    public UserDetailsService(UserCredentialRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userRepository.findByEmail((username)).orElseThrow(() -> new UsernameNotFoundException("User not found with email : " +  username));
    }
}
