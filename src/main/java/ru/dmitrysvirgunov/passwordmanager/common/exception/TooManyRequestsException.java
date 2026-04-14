package ru.dmitrysvirgunov.passwordmanager.common.exception;

public class TooManyRequestsException extends ApplicationException {

    public TooManyRequestsException(String message) {
        super(message);
    }
}