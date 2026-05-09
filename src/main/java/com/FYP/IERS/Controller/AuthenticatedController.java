package com.FYP.IERS.Controller;

import com.FYP.IERS.DTO.AuthenticationDTO.AuthenticationResponse;
import com.FYP.IERS.DTO.AuthenticationDTO.SetPasswordRequest;
import com.FYP.IERS.Service.AuthenticationService.AuthenticationService;
import com.FYP.IERS.utils.JwtUtil;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping({"/auth", "/api/auth"})
public class AuthenticatedController {

    private final AuthenticationService authenticationService;
    private final JwtUtil jwtUtil;

    public AuthenticatedController(AuthenticationService authenticationService, JwtUtil jwtUtil) {
        this.authenticationService = authenticationService;
        this.jwtUtil = jwtUtil;
    }

    @GetMapping("/validate")
    public ResponseEntity<String> validateTokenAndGetUsername(@RequestHeader("Authorization") String authorizationHeader) {
        if (!authorizationHeader.startsWith("Bearer ")) {
            return ResponseEntity.badRequest().body("Invalid Authorization header format");
        }

        String token = authorizationHeader.substring(7);
        String username = jwtUtil.extractUsername(token);
        return ResponseEntity.ok(username);
    }

    @PostMapping("/set-password")
    public ResponseEntity<AuthenticationResponse> setPassword(@RequestBody SetPasswordRequest request,
                                                              Authentication authentication) {
        if (authentication == null || authentication.getName() == null) {
            return ResponseEntity.status(401)
                    .body(AuthenticationResponse.builder()
                            .success(false)
                            .message("Unauthorized")
                            .timestamp(System.currentTimeMillis())
                            .build());
        }

        AuthenticationResponse response = authenticationService.setLocalPassword(
                authentication.getName(),
                request.getNewPassword()
        );

        return ResponseEntity.ok(response);
    }
}

