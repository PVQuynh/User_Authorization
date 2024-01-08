package com.security.jwt.exception;

public class RefreshTokenFailedException extends  RuntimeException {
    public  RefreshTokenFailedException(String message) {
        super(message);
    }
}
