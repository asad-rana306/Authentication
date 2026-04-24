package com.FYP.IERS.Entity;

import jakarta.persistence.*;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.List;

@Entity
@Table(name = "users")
@Data
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String userName;
    private String password;
    private String email;
    private String phoneNumber;
    private String authProvider = "LOCAL";
    private String providerSubject;
    private LocalDateTime emailVerifiedAt;

    // It will automatically create a "user_roles" table in PostgreSQL with "user_id" and "role_name"
    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(
            name = "user_roles",
            joinColumns = @JoinColumn(name = "user_id")
    )
    @Column(name = "role_name")
    private List<String> roles;

    // Professional Authentication Fields
    private int failedLoginAttempts = 0;
    private boolean accountLocked = false;
    private LocalDateTime accountLockedUntil;
    private LocalDateTime lastLoginAttempt;
    private LocalDateTime lastSuccessfulLogin;
    private boolean enabled = true;
    private LocalDateTime createdAt = LocalDateTime.now();
    private LocalDateTime updatedAt = LocalDateTime.now();

    // One-time email verification for login
    private String signupOtpCode;
    private LocalDateTime signupExpiresAt;
    private int signupAttempts = 0;
    private LocalDateTime signupSentAt;

    // Forgot-password verification state
    private String passwordResetOtpCode;
    private LocalDateTime passwordResetOtpExpiresAt;
    private int passwordResetOtpAttempts = 0;
    private LocalDateTime passwordResetOtpSentAt;
}