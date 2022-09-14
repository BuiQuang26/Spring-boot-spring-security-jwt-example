package com.example.springsecurityjwtexample.security.jwt;

import com.example.springsecurityjwtexample.domain.model.Role;
import com.example.springsecurityjwtexample.domain.model.User;
import com.example.springsecurityjwtexample.repository.UserRepository;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import java.security.Key;
import java.util.Date;
import java.util.stream.Collectors;

@Component
public class JwtUtil {

    @Autowired
    UserRepository userRepository;
    @Autowired
    BCryptPasswordEncoder passwordEncoder;
    @Value("${spring-boot-app.jjwt.secret-key}")
    private String secretKey;
    private Key key;

    @PostConstruct
    public void init() {
        key = Keys.hmacShaKeyFor(secretKey.getBytes());

        User user = new User();
        user.setUsername("admin");
        user.setPassword(passwordEncoder.encode("admin"));
        userRepository.save(user);
    }

    public String generateToken(User user, Long expirationTime) {
        String roles = user.getRoles().stream().map(Role::getName).collect(Collectors.joining(","));
        Long now = (new Date()).getTime();
        return Jwts.builder().setSubject(user.getUsername()).claim("user_id", user.getId()).claim("user_role", roles).signWith(key).setExpiration(new Date(now + expirationTime)).compact();

    }

    public Claims getClaims(String token) throws ExpiredJwtException, UnsupportedJwtException, MalformedJwtException, SignatureException, IllegalArgumentException {
        return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody();
    }

}
