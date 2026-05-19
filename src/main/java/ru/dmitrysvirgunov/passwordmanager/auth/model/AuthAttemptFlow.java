package ru.dmitrysvirgunov.passwordmanager.auth.model;

public enum AuthAttemptFlow {
    REGISTER,
    LOGIN,
    PRELOGIN,
    VERIFY_EMAIL,
    RESEND_VERIFICATION,
    PASSWORD_RESET_REQUEST,
    MFA_RESET,
    NEW_DEVICE_CONFIRMATION
}
