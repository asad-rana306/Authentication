package com.FYP.IERS.Config;

import com.FYP.IERS.DTO.AuthenticationDTO.AuthenticationResponse;
import com.FYP.IERS.Exception.AdminOperationException;
import com.FYP.IERS.Exception.AccountLockedException;
import com.FYP.IERS.Exception.InvalidCredentialsException;
import com.FYP.IERS.Exception.UserNotFoundException;
import com.FYP.IERS.Exception.UserDisabledException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger logger = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(AccountLockedException.class)
    public ResponseEntity<AuthenticationResponse> handleAccountLocked(AccountLockedException e) {
        logger.warn("[AUTH][ACCOUNT_LOCKED] message={}", e.getMessage());
        return ResponseEntity
                .status(HttpStatus.LOCKED)
                .body(AuthenticationResponse.builder()
                        .success(false)
                        .message(e.getMessage())
                        .timestamp(System.currentTimeMillis())
                        .build());
    }

    @ExceptionHandler(InvalidCredentialsException.class)
    public ResponseEntity<AuthenticationResponse> handleInvalidCredentials(InvalidCredentialsException e) {
        logger.warn("[AUTH][INVALID_CREDENTIALS] message={}", e.getMessage());
        return ResponseEntity
                .status(HttpStatus.UNAUTHORIZED)
                .body(AuthenticationResponse.builder()
                        .success(false)
                        .message(e.getMessage())
                        .remainingAttempts(e.getRemainingAttempts())
                        .timestamp(System.currentTimeMillis())
                        .build());
    }

    @ExceptionHandler(UserDisabledException.class)
    public ResponseEntity<AuthenticationResponse> handleUserDisabled(UserDisabledException e) {
        logger.warn("[AUTH][USER_DISABLED] message={}", e.getMessage());
        return ResponseEntity
                .status(HttpStatus.FORBIDDEN)
                .body(AuthenticationResponse.builder()
                        .success(false)
                        .message(e.getMessage())
                        .timestamp(System.currentTimeMillis())
                        .build());
    }

    @ExceptionHandler(UserNotFoundException.class)
    public ResponseEntity<AuthenticationResponse> handleUserNotFound(UserNotFoundException e) {
        logger.warn("[ADMIN][DELETE_USER][NOT_FOUND] message={}", e.getMessage());
        return ResponseEntity
                .status(HttpStatus.NOT_FOUND)
                .body(AuthenticationResponse.builder()
                        .success(false)
                        .message(e.getMessage())
                        .timestamp(System.currentTimeMillis())
                        .build());
    }

    @ExceptionHandler(AdminOperationException.class)
    public ResponseEntity<AuthenticationResponse> handleAdminOperation(AdminOperationException e) {
        logger.warn("[ADMIN][OPERATION_REJECTED] message={}", e.getMessage());
        return ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .body(AuthenticationResponse.builder()
                        .success(false)
                        .message(e.getMessage())
                        .timestamp(System.currentTimeMillis())
                        .build());
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<AuthenticationResponse> handleGeneralException(Exception e) {
        logger.error("[GLOBAL][UNHANDLED_EXCEPTION]", e);
        return ResponseEntity
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(AuthenticationResponse.builder()
                        .success(false)
                        .message("An error occurred: " + e.getMessage())
                        .timestamp(System.currentTimeMillis())
                        .build());
    }
}

