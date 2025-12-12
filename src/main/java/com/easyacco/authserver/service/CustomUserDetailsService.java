package com.easyacco.authserver.service;

import com.easyacco.authserver.dto.UserDetailsDTO;
import com.easyacco.authserver.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        UserDetailsDTO userDetails = userRepository.getUserDetailsByUserName(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));

        return User.withUsername(userDetails.getUserName())
                .password(userDetails.getPassword())
                .authorities(userDetails.getRoles().split(",")) // convert CSV → authorities
                .build();
    }
}