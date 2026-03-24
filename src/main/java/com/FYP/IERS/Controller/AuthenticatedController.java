package com.FYP.IERS.Controller;

import com.FYP.IERS.DTO.AuthenticationDTO.AuthenticationResponse;
import com.FYP.IERS.DTO.AuthenticationDTO.SetPasswordRequest;
import com.FYP.IERS.Service.AuthenticationService.AuthenticationService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class AuthenticatedController {

    private final AuthenticationService authenticationService;

    public AuthenticatedController(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
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

