package com.example.springsecurityjwtexample.helper;

import com.example.springsecurityjwtexample.domain.model.User;
import com.example.springsecurityjwtexample.repository.UserRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import java.security.Key;
import java.util.Date;

@Component
public class JwtUtil {

    @Value("${spring-boot-app.jjwt.secret-key}")
    private String secretKey;

    @Autowired
    UserRepository userRepository;

    @Autowired
    BCryptPasswordEncoder passwordEncoder;

    private Key key;

    @PostConstruct
    public void init() {
        key = Keys.hmacShaKeyFor(secretKey.getBytes());
        User user = new User();
        user.setUsername("admin");
        user.setPassword(passwordEncoder.encode("admin"));
        System.out.println(userRepository.save(user));
    }

    public String generateToken(User user, Long expirationTime){

        final Date now = new Date();
        return Jwts.builder().setSubject(user.getUsername())
                .claim("user_id", user.getId())
                .claim("user_role", user.getRoles())
                .signWith(key)
                .setExpiration(new Date(now.getTime() + expirationTime))
                .compact();

    }

    public Claims getClaims(String token){
        return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody();
    }

}
