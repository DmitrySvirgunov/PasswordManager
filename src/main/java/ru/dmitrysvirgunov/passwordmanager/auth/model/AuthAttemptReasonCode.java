package ru.dmitrysvirgunov.passwordmanager.auth.model;

public enum AuthAttemptReasonCode {
    EMAIL_RATE_LIMIT,
    IP_RATE_LIMIT,
    EMAIL_AND_IP_RATE_LIMIT,
    LOGIN_RATE_LIMIT,
    RESET_RATE_LIMIT,
    SUSPICIOUS_PATTERN,
    UNKNOWN_EMAIL,
    INVALID_TOKEN,
    UNVERIFIED_EMAIL
}
