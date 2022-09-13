package com.example.springsecurityjwtexample.security;

import com.example.springsecurityjwtexample.domain.Response.HttpResponse;
import com.example.springsecurityjwtexample.domain.Response.HttpResponseError;
import com.example.springsecurityjwtexample.domain.model.User;
import com.example.springsecurityjwtexample.helper.JwtUtil;
import com.example.springsecurityjwtexample.repository.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Map;

public class CustomAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;

    private final UserRepository userRepository;

    public CustomAuthenticationFilter(AuthenticationManager authenticationManager, JwtUtil jwtUtil, UserRepository userRepository) {
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
        this.userRepository = userRepository;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        try {
            InputStream inputStream = request.getInputStream();
            Map auth = new ObjectMapper().readValue(inputStream, Map.class);

            if(auth.get("username") == null || auth.get("username").equals("") || auth.get("password") == null || auth.get("password").equals("")){
                throw new RuntimeException("username or password invalid");
            }

            return authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(auth.get("username"), auth.get("password")));

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        User user = userRepository.findByUsername(authResult.getName()).orElseThrow();
        String accessToken = jwtUtil.generateToken(user, 20*60*1000L);
        String refreshToken = jwtUtil.generateToken(user, 24*60*60*1000L);
        Map<String, String> data = Map.of("accessToken", accessToken,"refreshToken", refreshToken);
        HttpResponse re = new HttpResponse(true, 200, "Login successful", data);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(HttpServletResponse.SC_OK);
        OutputStream responseStream = response.getOutputStream();
        ObjectMapper mapper = new ObjectMapper();
        mapper.writeValue(responseStream, re);
        responseStream.flush();
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        HttpResponseError re = new HttpResponseError(false, 401, HttpStatus.UNAUTHORIZED.name(), "Login failed: username or password incorrect");
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        OutputStream responseStream = response.getOutputStream();
        ObjectMapper mapper = new ObjectMapper();
        mapper.writeValue(responseStream, re);
        responseStream.flush();
    }
}
