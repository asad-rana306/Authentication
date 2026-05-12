package com.FYP.IERS.Controller;

import com.FYP.IERS.DTO.AuthenticationDTO.AuthenticationResponse;
import com.FYP.IERS.DTO.AuthenticationDTO.ForgotPasswordRequest;
import com.FYP.IERS.DTO.AuthenticationDTO.LoginRequest;
import com.FYP.IERS.DTO.AuthenticationDTO.ResetPasswordRequest;
import com.FYP.IERS.DTO.AuthenticationDTO.SignupRequest;
import com.FYP.IERS.DTO.AuthenticationDTO.VerifySignupOtpRequest; // NEW DTO
import com.FYP.IERS.DTO.AuthenticationDTO.ResendSignupOtpRequest; // NEW DTO
import com.FYP.IERS.Entity.User;
import com.FYP.IERS.Service.AuthenticationService.AuthenticationService;
import com.FYP.IERS.Service.AuthenticationService.UserServices;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@RestController
@RequestMapping({"/public", "/auth/public"})
public class PublicController {
    private static final Logger logger = LoggerFactory.getLogger(PublicController.class);

    private final UserServices userServices;
    private final AuthenticationService authenticationService;
    private final PasswordEncoder passwordEncoder;

    public PublicController(UserServices userServices,
                            AuthenticationService authenticationService,
                            PasswordEncoder passwordEncoder) {
        this.userServices = userServices;
        this.authenticationService = authenticationService;
        this.passwordEncoder = passwordEncoder;
    }

    // ==================== SIGNUP ====================

    @PostMapping("/signup")
    public ResponseEntity<AuthenticationResponse> signUp(@RequestBody SignupRequest request) {
        // Validate input
        if (request.getUserName() == null || request.getUserName().trim().isEmpty()) {
            return badRequestResponse("Username is required");
        }
        if (request.getPassword() == null || request.getPassword().length() < 6) {
            return badRequestResponse("Password must be at least 6 characters long");
        }
        if (request.getEmail() == null || !request.getEmail().contains("@")) {
            return badRequestResponse("Valid email address is required");
        }

        String normalizedEmail = request.getEmail().trim().toLowerCase();

        // Create new user
        User user = new User();
        user.setUserName(request.getUserName());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setEmail(normalizedEmail);
        user.setPhoneNumber(request.getPhoneNumber());

        // SET TO FALSE: User must verify OTP before they are enabled
        user.setEnabled(false);
        user.setFailedLoginAttempts(0);
        user.setAccountLocked(false);
        user.setCreatedAt(LocalDateTime.now());
        user.setUpdatedAt(LocalDateTime.now());

        // Initialize roles
        if (user.getRoles() == null) {
            user.setRoles(new ArrayList<>(List.of("USER")));
        }

        User savedUser = userServices.addUser(user);
        logger.info("[SIGNUP][REGISTER_SUCCESS] userId={}, userName={}", savedUser.getId(), savedUser.getUserName());

        // Send OTP for this exact newly-created user record.
        authenticationService.sendSignupOtp(savedUser.getId());

        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(AuthenticationResponse.builder()
                        .success(true)
                        .message("User registered successfully. Please check your email for the verification OTP.")
                        .userId(savedUser.getId())
                        .userName(savedUser.getUserName())
                        .timestamp(System.currentTimeMillis())
                        .build());
    }

    @PostMapping("/signup/verify")
    public ResponseEntity<AuthenticationResponse> verifySignupOtp(@RequestBody VerifySignupOtpRequest request) {
        if (request.getEmail() == null || request.getEmail().trim().isEmpty()) {
            return badRequestResponse("Email is required");
        }
        if (request.getOtp() == null || request.getOtp().isBlank()) {
            return badRequestResponse("Verification code is required");
        }

        logger.info("[SIGNUP][VERIFY_REQUEST] email={}", request.getEmail());

        // This service method should verify the OTP and set user.setEnabled(true)
        AuthenticationResponse response = authenticationService.verifySignupOtp(
                request.getEmail().trim().toLowerCase(),
                request.getOtp().trim()
        );

        return ResponseEntity.ok(response);
    }

    @PostMapping("/signup/resend-otp")
    public ResponseEntity<AuthenticationResponse> resendSignupOtp(@RequestBody ResendSignupOtpRequest request) {
        if (request.getEmail() == null || request.getEmail().trim().isEmpty()) {
            return badRequestResponse("Email is required");
        }

        logger.info("[SIGNUP][RESEND_REQUEST] email={}", request.getEmail());

        AuthenticationResponse response = authenticationService.resendSignupOtp(request.getEmail().trim().toLowerCase());
        return ResponseEntity.ok(response);
    }

    // ==================== LOGIN ====================

    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponse> login(@RequestBody LoginRequest request) {
        if (request.getUserName() == null || request.getUserName().trim().isEmpty()) {
            return badRequestResponse("Username is required");
        }
        if (request.getPassword() == null || request.getPassword().isEmpty()) {
            return badRequestResponse("Password is required");
        }

        logger.info("Processing login for user: {}", request.getUserName());

        // This service method should now return the JWT token directly upon successful password match,
        // provided the user is enabled (i.e., they verified their signup OTP).
        AuthenticationResponse response = authenticationService.authenticate(
                request.getUserName(),
                request.getPassword()
        );

        return ResponseEntity.ok(response);
    }

    // ==================== FORGOT PASSWORD ====================

    @PostMapping("/forgot-password")
    public ResponseEntity<AuthenticationResponse> forgotPasswordAndGetOtpOnly(@RequestBody ForgotPasswordRequest request) {
        if (request.getEmail() == null || request.getEmail().trim().isEmpty()) {
            return badRequestResponse("Email is required");
        }

        AuthenticationResponse response = authenticationService.requestPasswordResetOtp(request.getEmail().trim());
        return ResponseEntity.ok(response);
    }

    @PostMapping("/forgot-password/reset")
    public ResponseEntity<AuthenticationResponse> resetPasswordAfterGettingOtp(@RequestBody ResetPasswordRequest request) {
        if (request.getEmail() == null || request.getEmail().trim().isEmpty()) {
            return badRequestResponse("Email is required");
        }
        if (request.getOtp() == null || request.getOtp().trim().isEmpty()) {
            return badRequestResponse("Reset code is required");
        }
        if (request.getNewPassword() == null || request.getNewPassword().length() < 6) {
            return badRequestResponse("New password must be at least 6 characters long");
        }

        AuthenticationResponse response = authenticationService.resetPasswordWithOtp(
                request.getEmail().trim(),
                request.getOtp().trim(),
                request.getNewPassword()
        );

        return ResponseEntity.ok(response);
    }

    // ==================== HEALTH CHECK ====================

    @GetMapping("/health")
    public ResponseEntity<AuthenticationResponse> health() {
        return ResponseEntity.ok(
                AuthenticationResponse.builder()
                        .success(true)
                        .message("Authentication service is running")
                        .timestamp(System.currentTimeMillis())
                        .build()
        );
    }

    // ==================== HELPER METHODS ====================

    private ResponseEntity<AuthenticationResponse> badRequestResponse(String message) {
        return ResponseEntity
                .badRequest()
                .body(AuthenticationResponse.builder()
                        .success(false)
                        .message(message)
                        .timestamp(System.currentTimeMillis())
                        .build());
    }
}