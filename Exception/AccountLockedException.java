package com.FYP.IERS.Exception;

public class AccountLockedException extends RuntimeException {
    private final long lockDurationMinutes;

    public AccountLockedException(String message, long lockDurationMinutes) {
        super(message);
        this.lockDurationMinutes = lockDurationMinutes;
    }

    public long getLockDurationMinutes() {
        return lockDurationMinutes;
    }
}

