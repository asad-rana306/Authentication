package com.FYP.IERS.Service;

import com.FYP.IERS.DTO.AuthenticationResponse;
import com.FYP.IERS.Entity.User;
import com.FYP.IERS.Exception.AccountLockedException;
import com.FYP.IERS.Exception.InvalidCredentialsException;
import com.FYP.IERS.Exception.UserDisabledException;
import com.FYP.IERS.Repository.UserRepository;
import com.FYP.IERS.utils.JwtUtil;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;

@Service
@Transactional
public class AuthenticationService {

    private static final int MAX_FAILED_ATTEMPTS = 3;
    private static final long LOCK_TIME_MINUTES = 15;

    private static final int OTP_EXPIRY_MINUTES = 5;
    private static final int OTP_MAX_ATTEMPTS = 5;
    private static final int OTP_RESEND_COOLDOWN_SECONDS = 30;

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final JwtUtil jwtUtil;
    private final EmailService emailService;
    private final PasswordEncoder passwordEncoder;
    private final SecureRandom secureRandom = new SecureRandom();

    public AuthenticationService(AuthenticationManager authenticationManager,
                                 UserRepository userRepository,
                                 JwtUtil jwtUtil,
                                 EmailService emailService,
                                 PasswordEncoder passwordEncoder) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.jwtUtil = jwtUtil;
        this.emailService = emailService;
        this.passwordEncoder = passwordEncoder;
    }

    /**
     * Authenticate user with professional security features
     */
    @Transactional(noRollbackFor = {InvalidCredentialsException.class, AccountLockedException.class})
    public AuthenticationResponse authenticate(String userName, String password) {
        User user = userRepository.findByUserName(userName);

        // Check if user exists
        if (user == null) {
            return AuthenticationResponse.builder()
                    .success(false)
                    .message("Invalid username or password")
                    .remainingAttempts(MAX_FAILED_ATTEMPTS)
                    .timestamp(System.currentTimeMillis())
                    .build();
        }

        // Check if user is enabled (Requires Signup OTP verification first)
        if (!user.isEnabled()) {
            throw new UserDisabledException("Your account has not been verified. Please check your email for the verification code.");
        }

        // Check if account is locked
        if (user.isAccountLocked()) {
            if (isLockExpired(user)) {
                // Unlock the account
                unlockAccount(user);
                userRepository.save(user);
            } else {
                long remainingMinutes = getRemainingLockTime(user);
                throw new AccountLockedException(
                        "Account is locked due to multiple failed login attempts. Try again in " + remainingMinutes + " minutes.",
                        remainingMinutes
                );
            }
        }

        // Try to authenticate
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(userName, password)
            );

            // Password is valid: clear lock counters and issue JWT directly.
            resetFailedAttempts(user);
            user.setLastSuccessfulLogin(LocalDateTime.now());
            user.setUpdatedAt(LocalDateTime.now());
            userRepository.save(user);

            String token = jwtUtil.generateToken(userName);

            return AuthenticationResponse.builder()
                    .success(true)
                    .message("Login successful")
                    .token(token)
                    .userId(user.getId())
                    .userName(user.getUserName())
                    .timestamp(System.currentTimeMillis())
                    .build();

        } catch (BadCredentialsException e) {
            // Handle failed login attempt
            user.setLastLoginAttempt(LocalDateTime.now());
            user.setFailedLoginAttempts(user.getFailedLoginAttempts() + 1);

            int remainingAttempts = MAX_FAILED_ATTEMPTS - user.getFailedLoginAttempts();

            // Lock account if max attempts reached
            if (user.getFailedLoginAttempts() >= MAX_FAILED_ATTEMPTS) {
                lockAccount(user);
                userRepository.save(user); // This save will now persist!
                throw new AccountLockedException(
                        "Account locked due to 3 failed login attempts. Please try again after 15 minutes.",
                        LOCK_TIME_MINUTES
                );
            }

            userRepository.save(user); // This save will now persist!

            throw new InvalidCredentialsException(
                    "Invalid username or password. " + remainingAttempts + " attempt(s) remaining before account lock.",
                    remainingAttempts
            );
        }
    }

    // ==================== SIGNUP OTP METHODS ====================

    /**
     * Send initial signup OTP
     */
    public void sendSignupOtp(String email) {
        userRepository.findByEmail(email).ifPresent(user -> {
            issueSignupOtp(user);
            userRepository.save(user);
        });
    }

    /**
     * Verify email OTP for new user signup
     */
    @Transactional(noRollbackFor = InvalidCredentialsException.class)
    public AuthenticationResponse verifySignupOtp(String email, String otp) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new InvalidCredentialsException("Invalid verification request.", 0));

        if (user.isEnabled()) {
            throw new InvalidCredentialsException("User is already verified. Please login.", 0);
        }

        if (user.getLoginOtpCode() == null || user.getLoginOtpExpiresAt() == null) {
            throw new InvalidCredentialsException("No pending verification found. Please request a new code.", 0);
        }

        if (LocalDateTime.now().isAfter(user.getLoginOtpExpiresAt())) {
            clearSignupOtpChallenge(user);
            userRepository.save(user);
            throw new InvalidCredentialsException("Verification code expired. Please request a new one.", 0);
        }

        if (user.getLoginOtpAttempts() >= OTP_MAX_ATTEMPTS) {
            clearSignupOtpChallenge(user);
            userRepository.save(user);
            throw new InvalidCredentialsException("Too many invalid codes. Please request a new one.", 0);
        }

        if (!user.getLoginOtpCode().equals(otp)) {
            user.setLoginOtpAttempts(user.getLoginOtpAttempts() + 1);
            user.setUpdatedAt(LocalDateTime.now());
            userRepository.save(user);
            int remaining = Math.max(0, OTP_MAX_ATTEMPTS - user.getLoginOtpAttempts());
            throw new InvalidCredentialsException("Invalid verification code. " + remaining + " attempt(s) remaining.", remaining);
        }

        // Verification successful: Enable the user!
        user.setEnabled(true);
        clearSignupOtpChallenge(user);
        user.setUpdatedAt(LocalDateTime.now());
        userRepository.save(user);

        return AuthenticationResponse.builder()
                .success(true)
                .message("Email verified successfully! You can now login.")
                .userId(user.getId())
                .userName(user.getUserName())
                .timestamp(System.currentTimeMillis())
                .build();
    }

    /**
     * Resend the email OTP for signup verification
     */
    @Transactional(noRollbackFor = InvalidCredentialsException.class)
    public AuthenticationResponse resendSignupOtp(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new InvalidCredentialsException("Invalid request. User not found.", 0));

        if (user.isEnabled()) {
            throw new InvalidCredentialsException("User is already verified. Please login.", 0);
        }

        if (user.getLoginOtpSentAt() != null) {
            long secondsSinceLastSend = ChronoUnit.SECONDS.between(user.getLoginOtpSentAt(), LocalDateTime.now());
            if (secondsSinceLastSend < OTP_RESEND_COOLDOWN_SECONDS) {
                long waitSeconds = OTP_RESEND_COOLDOWN_SECONDS - secondsSinceLastSend;
                throw new InvalidCredentialsException("Please wait " + waitSeconds + " second(s) before requesting another code.", 0);
            }
        }

        issueSignupOtp(user);
        user.setUpdatedAt(LocalDateTime.now());
        userRepository.save(user);

        return AuthenticationResponse.builder()
                .success(true)
                .message("A new verification code has been sent to your email.")
                .emailVerificationRequired(true)
                .otpExpiresInSeconds(OTP_EXPIRY_MINUTES * 60L)
                .userId(user.getId())
                .userName(user.getUserName())
                .timestamp(System.currentTimeMillis())
                .build();
    }

    /**
     * Issue a one-time password (OTP) to the user's email for signup verification
     */
    private void issueSignupOtp(User user) {
        validateUserHasEmail(user);

        String otp = generateSixDigitOtp();
        user.setLoginOtpCode(otp); // Reusing loginOtp fields for signup OTP
        user.setLoginOtpExpiresAt(LocalDateTime.now().plusMinutes(OTP_EXPIRY_MINUTES));
        user.setLoginOtpAttempts(0);
        user.setLoginOtpSentAt(LocalDateTime.now());

        // Note: You might want to update your EmailService to have a generic "sendVerificationOtp" method,
        // but using sendLoginOtp works fine for now as it probably just sends the code.
        emailService.sendLoginOtp(user.getEmail(), user.getUserName(), otp, OTP_EXPIRY_MINUTES);
    }

    /**
     * Clear the OTP challenge data from the user entity
     */
    private void clearSignupOtpChallenge(User user) {
        user.setLoginOtpCode(null);
        user.setLoginOtpExpiresAt(null);
        user.setLoginOtpAttempts(0);
        user.setLoginOtpSentAt(null);
    }

    // ==================== FORGOT PASSWORD METHODS ====================

    /**
     * Request a password reset OTP to be sent to the user's email
     */
    public AuthenticationResponse requestPasswordResetOtp(String email) {
        if (email == null || email.isBlank()) {
            return genericForgotPasswordResponse();
        }

        userRepository.findByEmail(email.trim()).ifPresent(user -> {
            issuePasswordResetOtp(user);
            user.setUpdatedAt(LocalDateTime.now());
            userRepository.save(user);
        });

        return genericForgotPasswordResponse();
    }

    /**
     * Reset the password using the OTP received on email
     */
    @Transactional(noRollbackFor = InvalidCredentialsException.class)
    public AuthenticationResponse resetPasswordWithOtp(String email, String otp, String newPassword) {
        User user = userRepository.findByEmail(email.trim())
                .orElseThrow(() -> new InvalidCredentialsException("Invalid or expired reset request.", 0));

        if (user.getPasswordResetOtpCode() == null || user.getPasswordResetOtpExpiresAt() == null) {
            throw new InvalidCredentialsException("No pending password reset found.", 0);
        }

        if (LocalDateTime.now().isAfter(user.getPasswordResetOtpExpiresAt())) {
            clearPasswordResetChallenge(user);
            userRepository.save(user);
            throw new InvalidCredentialsException("Reset code expired. Request a new one.", 0);
        }

        if (user.getPasswordResetOtpAttempts() >= OTP_MAX_ATTEMPTS) {
            clearPasswordResetChallenge(user);
            userRepository.save(user);
            throw new InvalidCredentialsException("Too many invalid reset attempts. Request a new code.", 0);
        }

        if (!user.getPasswordResetOtpCode().equals(otp)) {
            user.setPasswordResetOtpAttempts(user.getPasswordResetOtpAttempts() + 1);
            user.setUpdatedAt(LocalDateTime.now());
            userRepository.save(user);
            int remaining = Math.max(0, OTP_MAX_ATTEMPTS - user.getPasswordResetOtpAttempts());
            throw new InvalidCredentialsException("Invalid reset code. " + remaining + " attempt(s) remaining.", remaining);
        }

        user.setPassword(passwordEncoder.encode(newPassword));
        clearPasswordResetChallenge(user);
        clearSignupOtpChallenge(user);
        resetFailedAttempts(user);
        user.setUpdatedAt(LocalDateTime.now());
        userRepository.save(user);

        return AuthenticationResponse.builder()
                .success(true)
                .message("Password reset successful. Please login with your new password.")
                .timestamp(System.currentTimeMillis())
                .build();
    }

    private void issuePasswordResetOtp(User user) {
        validateUserHasEmail(user);

        if (user.getPasswordResetOtpSentAt() != null) {
            long secondsSinceLastSend = ChronoUnit.SECONDS.between(user.getPasswordResetOtpSentAt(), LocalDateTime.now());
            if (secondsSinceLastSend < OTP_RESEND_COOLDOWN_SECONDS) {
                return;
            }
        }

        String otp = generateSixDigitOtp();
        user.setPasswordResetOtpCode(otp);
        user.setPasswordResetOtpExpiresAt(LocalDateTime.now().plusMinutes(OTP_EXPIRY_MINUTES));
        user.setPasswordResetOtpAttempts(0);
        user.setPasswordResetOtpSentAt(LocalDateTime.now());

        emailService.sendPasswordResetOtp(user.getEmail(), user.getUserName(), otp, OTP_EXPIRY_MINUTES);
    }

    // ==================== HELPER METHODS ====================

    private String generateSixDigitOtp() {
        return String.valueOf(100000 + secureRandom.nextInt(900000));
    }

    private void validateUserHasEmail(User user) {
        if (user.getEmail() == null || user.getEmail().isBlank()) {
            throw new InvalidCredentialsException("No email configured for this account. Contact administrator.", 0);
        }
    }

    private AuthenticationResponse genericForgotPasswordResponse() {
        return AuthenticationResponse.builder()
                .success(true)
                .message("If an account exists for that email, a reset code has been sent.")
                .timestamp(System.currentTimeMillis())
                .build();
    }

    private void clearPasswordResetChallenge(User user) {
        user.setPasswordResetOtpCode(null);
        user.setPasswordResetOtpExpiresAt(null);
        user.setPasswordResetOtpAttempts(0);
        user.setPasswordResetOtpSentAt(null);
    }

    private void resetFailedAttempts(User user) {
        user.setFailedLoginAttempts(0);
        user.setAccountLocked(false);
        user.setAccountLockedUntil(null);
    }

    private void lockAccount(User user) {
        user.setAccountLocked(true);
        user.setAccountLockedUntil(LocalDateTime.now().plusMinutes(LOCK_TIME_MINUTES));
    }

    private void unlockAccount(User user) {
        user.setAccountLocked(false);
        user.setAccountLockedUntil(null);
        user.setFailedLoginAttempts(0);
    }

    private boolean isLockExpired(User user) {
        return user.getAccountLockedUntil() != null && LocalDateTime.now().isAfter(user.getAccountLockedUntil());
    }

    private long getRemainingLockTime(User user) {
        if (user.getAccountLockedUntil() == null) {
            return LOCK_TIME_MINUTES;
        }
        long secondsRemaining = ChronoUnit.SECONDS.between(LocalDateTime.now(), user.getAccountLockedUntil());
        return Math.max(1, (secondsRemaining + 59) / 60); // Round up to minutes
    }

    public AuthenticationResponse getUserLoginStats(String userName) {
        User user = userRepository.findByUserName(userName);

        if (user == null) {
            return AuthenticationResponse.builder()
                    .success(false)
                    .message("User not found")
                    .timestamp(System.currentTimeMillis())
                    .build();
        }

        return AuthenticationResponse.builder()
                .success(true)
                .userId(user.getId())
                .userName(user.getUserName())
                .remainingAttempts(MAX_FAILED_ATTEMPTS - user.getFailedLoginAttempts())
                .timestamp(System.currentTimeMillis())
                .build();
    }
}