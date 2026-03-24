package com.FYP.IERS.DTO;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class SignupRequest {
    private String userName;
    private String password;
    private String email;
    private String phoneNumber;
}

