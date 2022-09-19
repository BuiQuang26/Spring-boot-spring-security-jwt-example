package com.example.springsecurityjwtexample.service;

import com.example.springsecurityjwtexample.domain.model.User;
import com.example.springsecurityjwtexample.repository.UserRepository;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserService {

    private final UserRepository userRepository;

    private final BCryptPasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository, BCryptPasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public User register(User user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return userRepository.save(user);
    }

    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public List<User> getAll() {
        return userRepository.findAll();
    }
}
