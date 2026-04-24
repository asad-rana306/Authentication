package com.FYP.IERS.Config;

import com.FYP.IERS.DTO.AuthenticationDTO.AuthenticationResponse;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

@Component
public class GoogleOAuth2FailureHandler implements AuthenticationFailureHandler {

    public GoogleOAuth2FailureHandler() {
    }

    @Override
    public void onAuthenticationFailure(HttpServletRequest request,
                                        HttpServletResponse response,
                                        AuthenticationException exception) throws IOException, ServletException {
        AuthenticationResponse authResponse = AuthenticationResponse.builder()
                .success(false)
                .message("Google authentication failed: " + exception.getMessage())
                .timestamp(System.currentTimeMillis())
                .build();

        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.getWriter().write(buildJson(authResponse));
    }

    private String buildJson(AuthenticationResponse response) {
        return "{"
                + "\"success\":" + response.isSuccess() + ","
                + "\"message\":\"" + escape(response.getMessage()) + "\"," 
                + "\"timestamp\":" + response.getTimestamp()
                + "}";
    }

    private String escape(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}

