package com.FYP.IERS.Config;

import com.FYP.IERS.FIlter.JwtFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import jakarta.servlet.http.HttpServletResponse;
import java.nio.charset.StandardCharsets;
import java.util.List;

@Configuration
public class SpringSecurity {

    @Autowired
    private JwtFilter jwtFilter;

    @Autowired
    private GoogleOAuth2SuccessHandler googleOAuth2SuccessHandler;

    @Autowired
    private GoogleOAuth2FailureHandler googleOAuth2FailureHandler;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        // 1. Disable CSRF (Safe for JWT/Stateless APIs)
        http.csrf(csrf -> csrf.disable());

        // 2. Enable CORS
        http.cors(Customizer.withDefaults());

        // 3. Configure Route Permissions
        http.authorizeHttpRequests(auth -> auth
                // Allow all OPTIONS requests (Pre-flight CORS checks)
                .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()

                // FIXED: Added /auth/public/** so your signup route is actually accessible
                .requestMatchers("/auth/public/**", "/public/**").permitAll()

                // OAuth2 login endpoints
                .requestMatchers("/oauth2/**", "/login/oauth2/**").permitAll()

                // Swagger Documentation (Public)
                .requestMatchers(
                        "/swagger-ui/**",
                        "/v3/api-docs/**",
                        "/swagger-ui.html"
                ).permitAll()

                // Admin-only endpoints
                .requestMatchers(HttpMethod.DELETE, "/admin/users/**").hasRole("ADMIN")

                // ALL other requests require a valid JWT Token
                .anyRequest().authenticated()
        );

        // 4. OAuth2 authorization flow needs temporary session state.
        http.sessionManagement(session ->
                session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
        );

        // 5. Enable OAuth2 login with JSON success/failure responses.
        http.oauth2Login(oauth2 -> oauth2
                .successHandler(googleOAuth2SuccessHandler)
                .failureHandler(googleOAuth2FailureHandler)
        );

        // 6. Add JWT Filter before standard authentication
        http.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);

        // Return 401 for missing/invalid token and 403 only for true access-denied cases.
        http.exceptionHandling(ex -> ex
                .authenticationEntryPoint((request, response, authException) -> {
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                    response.setCharacterEncoding(StandardCharsets.UTF_8.name());
                    response.getWriter().write("{\"success\":false,\"message\":\"Unauthorized: missing or invalid token\"}");
                })
                .accessDeniedHandler((request, response, accessDeniedException) -> {
                    response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                    response.setCharacterEncoding(StandardCharsets.UTF_8.name());
                    response.getWriter().write("{\"success\":false,\"message\":\"Forbidden: insufficient permissions\"}");
                })
        );

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();

        // Allow browser clients from any deployed frontend origin.
        config.setAllowedOriginPatterns(List.of("*"));
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of("*"));
        config.setExposedHeaders(List.of("Authorization", "Content-Disposition"));

        // FIXED: Changed to true. Many frontends (like Axios or Fetch) require this
        // to be true when crossing origins, even if you are just passing headers.
        config.setAllowCredentials(true);
        config.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
}