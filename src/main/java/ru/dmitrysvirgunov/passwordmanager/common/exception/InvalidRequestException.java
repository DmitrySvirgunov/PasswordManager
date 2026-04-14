package ru.dmitrysvirgunov.passwordmanager.common.exception;

public class InvalidRequestException extends ApplicationException {

    public InvalidRequestException(String message) {
        super(message);
    }

    public InvalidRequestException(String message, Throwable cause) {
        super(message, cause);
    }
}