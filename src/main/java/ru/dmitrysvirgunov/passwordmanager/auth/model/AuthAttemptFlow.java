package ru.dmitrysvirgunov.passwordmanager.auth.model;

public enum AuthAttemptFlow {
    REGISTER,
    LOGIN,
    RESEND_VERIFICATION,
    PASSWORD_RESET_REQUEST,
    MFA_RESET,
    NEW_DEVICE_CONFIRMATION
}
