package com.FYP.IERS.DTO.AuthenticationDTO;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthenticationResponse {
    private boolean success;
    private String message;
    private String token;
    private Integer remainingAttempts;
    private Long userId;
    private String userName;
    private Boolean emailVerificationRequired;
    private Long otpExpiresInSeconds;
    private long timestamp;
}
