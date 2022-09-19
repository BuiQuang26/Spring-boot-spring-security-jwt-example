package com.example.springsecurityjwtexample.security;

import com.example.springsecurityjwtexample.domain.Response.HttpResponseError;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.OutputStream;

@Component
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        OutputStream responseStream = response.getOutputStream();
        ObjectMapper mapper = new ObjectMapper();
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        HttpResponseError re;
        switch (response.getStatus()) {
            case 401 -> {
                re = new HttpResponseError(false, 401, HttpStatus.UNAUTHORIZED.name(), "Authorization failed");
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            }
            case 4011 -> {
                re = new HttpResponseError(false, 401, "TOKEN_EXPIRED", "Authorization failed");
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            }
            default -> {
                re = new HttpResponseError(false, 403, HttpStatus.FORBIDDEN.name(), "Access denied");
                response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            }
        }
        mapper.writeValue(responseStream, re);
        responseStream.flush();
    }
}
