package com.security.jwt.exception;

public class EmailNotFoundException extends  RuntimeException {
    public  EmailNotFoundException(String message) {
        super(message);
    }
}
