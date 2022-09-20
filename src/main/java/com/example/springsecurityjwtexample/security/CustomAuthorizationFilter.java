package com.example.springsecurityjwtexample.security;

import com.example.springsecurityjwtexample.security.jwt.JwtUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;

public class CustomAuthorizationFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;

    public CustomAuthorizationFilter(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        SecurityContextHolder.clearContext();
        if (request.getHeader(AUTHORIZATION) == null || !request.getHeader(AUTHORIZATION).startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
        } else {
            try {
                String token = request.getHeader(AUTHORIZATION).substring("Bearer ".length());
                Claims claims = jwtUtil.getClaims(token);
                String username = claims.getSubject();
                Long user_id = claims.get("user_id", Long.class);
                String roles = claims.get("user_role", String.class);
                List<SimpleGrantedAuthority> authorities = new ArrayList<>();
                if (!roles.equals("")) {
                    Arrays.stream(roles.split(",")).forEach(role -> {
                        authorities.add(new SimpleGrantedAuthority(role));
                    });
                }
                UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, null, authorities);
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                request.setAttribute("userID", user_id);
                request.setAttribute("username", username);
            } catch (ExpiredJwtException e) {
                System.out.println(e.getClass() + " : " + e.getMessage());
                response.setStatus(4011);
            } catch (UnsupportedJwtException e) {
                System.out.println(UnsupportedJwtException.class + " : " + e.getMessage());
                response.setStatus(4012);
            } catch (MalformedJwtException e) {
                System.out.println(MalformedJwtException.class + " : " + e.getMessage());
                response.setStatus(4013);
            } catch (SignatureException e) {
                System.out.println(SignatureException.class + " : " + e.getMessage());
                response.setStatus(4014);
            } catch (IllegalArgumentException e) {
                System.out.println(IllegalArgumentException.class + " : " + e.getMessage());
                response.setStatus(4015);
            }
            filterChain.doFilter(request, response);
        }
    }
}
