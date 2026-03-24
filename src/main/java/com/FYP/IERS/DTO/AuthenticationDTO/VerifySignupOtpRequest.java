package com.FYP.IERS.DTO;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class VerifySignupOtpRequest {
    private String email;
    private String otp;
}