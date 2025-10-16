package com.dianaglobal.loginregister.application.service.exception;

public class TooManyRequestsException extends RuntimeException {
    public TooManyRequestsException(String msg) { super(msg); }
}
