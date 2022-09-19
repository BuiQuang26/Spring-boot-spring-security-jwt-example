package com.example.springsecurityjwtexample.security;

import com.example.springsecurityjwtexample.domain.model.Role;
import com.example.springsecurityjwtexample.domain.model.User;
import com.example.springsecurityjwtexample.repository.RoleRepository;
import com.example.springsecurityjwtexample.repository.UserRepository;
import com.example.springsecurityjwtexample.security.jwt.JwtUtil;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

    private static final String[] AUTH_WHITELIST = {
            // -- Swagger UI v2
            "/v2/api-docs", "/swagger-resources", "/swagger-resources/**", "/configuration/ui", "/configuration/security", "/swagger-ui.html", "/webjars/**",
            // -- Swagger UI v3 (OpenAPI)
            "/v3/api-docs/**", "/swagger-ui/**",
            // other public endpoints of your API may be appended to this array
            "/api/user/login", "/api/user/register"};

    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final UserDetailsService userDetailService;
    private final CustomAuthenticationEntryPoint customAuthenticationEntryPoint;
    private final AccessDeniedHandlerCustom accessDeniedHandlerCustom;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final JwtUtil jwtUtil;

    public SecurityConfig(UserDetailService userDetailService, BCryptPasswordEncoder bCryptPasswordEncoder, CustomAuthenticationEntryPoint customAuthenticationEntryPoint, AccessDeniedHandlerCustom accessDeniedHandlerCustom, UserRepository userRepository, RoleRepository roleRepository, JwtUtil jwtUtil) {
        this.userDetailService = userDetailService;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
        this.customAuthenticationEntryPoint = customAuthenticationEntryPoint;
        this.accessDeniedHandlerCustom = accessDeniedHandlerCustom;
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.jwtUtil = jwtUtil;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        AuthenticationManagerBuilder authenticationManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
        authenticationManagerBuilder.userDetailsService(userDetailService).passwordEncoder(bCryptPasswordEncoder);

        AuthenticationManager authenticationManager = authenticationManagerBuilder.build();

        http.authenticationManager(authenticationManager);

        //handler exception
        http.exceptionHandling()
                .authenticationEntryPoint(customAuthenticationEntryPoint)
                .accessDeniedHandler(accessDeniedHandlerCustom);

        http.cors().and().csrf().disable();
        http.authorizeHttpRequests()
                .antMatchers(AUTH_WHITELIST).permitAll()
                .anyRequest().authenticated();

        CustomAuthenticationFilter authenticationFilter = new CustomAuthenticationFilter(authenticationManager, jwtUtil, userRepository);
        authenticationFilter.setFilterProcessesUrl("/api/user/login");
        http.addFilter(authenticationFilter);
        http.addFilterBefore(new CustomAuthorizationFilter(jwtUtil), UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    @Bean
    public void generateUserAdmin(){
        Role role = new Role();
        role.setName("ROLE_ADMIN");
        User user = new User();
        user.setName("admin");
        user.setUsername("admin");
        user.setPassword(bCryptPasswordEncoder.encode("admin"));
        roleRepository.save(role);
        user.addRole(role);
        userRepository.save(user);
        user.setPassword("admin");
        System.out.println("Generate admin : " + user);
    }

}
