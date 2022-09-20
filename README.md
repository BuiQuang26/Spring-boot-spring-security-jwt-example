# Spring boot: Spring security + jwt

## Dependency
pom
```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
	xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
	<modelVersion>4.0.0</modelVersion>
	<parent>
		<groupId>org.springframework.boot</groupId>
		<artifactId>spring-boot-starter-parent</artifactId>
		<version>2.7.3</version>
		<relativePath/> <!-- lookup parent from repository -->
	</parent>
	<groupId>com.example</groupId>
	<artifactId>spring-security-jwt-example</artifactId>
	<version>0.0.1-SNAPSHOT</version>
	<name>spring-security-jwt-example</name>
	<description>Demo project for Spring Boot</description>
	<properties>
		<java.version>17</java.version>
	</properties>
	<dependencies>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-data-jpa</artifactId>
		</dependency>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-security</artifactId>
		</dependency>
		<dependency>
			<groupId>io.jsonwebtoken</groupId>
			<artifactId>jjwt-api</artifactId>
			<version>0.11.5</version>
		</dependency>
		<dependency>
			<groupId>io.jsonwebtoken</groupId>
			<artifactId>jjwt-impl</artifactId>
			<version>0.11.5</version>
			<scope>runtime</scope>
		</dependency>
		<dependency>
			<groupId>io.jsonwebtoken</groupId>
			<artifactId>jjwt-jackson</artifactId>
			<version>0.11.5</version>
			<scope>runtime</scope>
		</dependency>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-web</artifactId>
		</dependency>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-validation</artifactId>
		</dependency>
		<dependency>
			<groupId>com.h2database</groupId>
			<artifactId>h2</artifactId>
			<scope>runtime</scope>
		</dependency>
		<dependency>
			<groupId>org.projectlombok</groupId>
			<artifactId>lombok</artifactId>
			<optional>true</optional>
		</dependency>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-test</artifactId>
			<scope>test</scope>
		</dependency>
		<dependency>
			<groupId>org.springframework.security</groupId>
			<artifactId>spring-security-test</artifactId>
			<scope>test</scope>
		</dependency>
		<dependency>
			<groupId>org.springdoc</groupId>
			<artifactId>springdoc-openapi-ui</artifactId>
			<version>1.6.10</version>
		</dependency>
	</dependencies>

	<build>
		<plugins>
			<plugin>
				<groupId>org.springframework.boot</groupId>
				<artifactId>spring-boot-maven-plugin</artifactId>
				<configuration>
					<excludes>
						<exclude>
							<groupId>org.projectlombok</groupId>
							<artifactId>lombok</artifactId>
						</exclude>
					</excludes>
				</configuration>
			</plugin>
		</plugins>
	</build>

</project>

```

## Security config

```java
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
}
```

## JWT provide

```java
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

```

## Custom authentication filter

```java
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
            if (auth.get("username") == null || auth.get("username").equals("") || auth.get("password") == null || auth.get("password").equals("")) {
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
        String accessToken = jwtUtil.generateToken(user, ACCESS_TOKEN_EXPIRED_TIME);
        String refreshToken = jwtUtil.generateToken(user, REFRESH_TOKEN_EXPIRED_TIME);
        Map<String, String> data = Map.of("accessToken", accessToken, "refreshToken", refreshToken);
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
```

## Custom authorization filter

```java
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
```

## Custom authentication entry point

```java
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

```

## Custom accessDenied handler

```java
@Component
public class AccessDeniedHandlerCustom implements AccessDeniedHandler {
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
        OutputStream responseStream = response.getOutputStream();
        ObjectMapper mapper = new ObjectMapper();
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        HttpResponseError re = new HttpResponseError(false, 403, HttpStatus.FORBIDDEN.name(), "Access denied");
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        mapper.writeValue(responseStream, re);
        responseStream.flush();
    }
}
```

## Security method
