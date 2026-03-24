package com.FYP.IERS.Config;

import com.FYP.IERS.DTO.AuthenticationDTO.AuthenticationResponse;
import com.FYP.IERS.Service.AuthenticationService.AuthenticationService;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

@Component
public class GoogleOAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final AuthenticationService authenticationService;
    private final ObjectMapper objectMapper;

    public GoogleOAuth2SuccessHandler(AuthenticationService authenticationService, ObjectMapper objectMapper) {
        this.authenticationService = authenticationService;
        this.objectMapper = objectMapper;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal();
        Map<String, Object> attributes = oauth2User.getAttributes();

        String email = stringValue(attributes.get("email"));
        String name = stringValue(attributes.get("name"));
        String subject = stringValue(attributes.get("sub"));

        AuthenticationResponse authResponse = authenticationService.authenticateWithGoogle(email, name, subject);

        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.getWriter().write(objectMapper.writeValueAsString(authResponse));
    }

    private String stringValue(Object value) {
        return value == null ? null : value.toString();
    }
}

