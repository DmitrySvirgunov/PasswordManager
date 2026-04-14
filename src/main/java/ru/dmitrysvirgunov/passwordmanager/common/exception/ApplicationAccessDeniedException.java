package ru.dmitrysvirgunov.passwordmanager.common.exception;

public class ApplicationAccessDeniedException extends ApplicationException {

    public ApplicationAccessDeniedException(String message) {
        super(message);
    }
}