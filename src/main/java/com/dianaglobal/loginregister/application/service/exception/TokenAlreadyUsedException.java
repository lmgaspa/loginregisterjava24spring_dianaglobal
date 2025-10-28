package com.dianaglobal.loginregister.application.service.exception;

public class TokenAlreadyUsedException extends RuntimeException {
    public TokenAlreadyUsedException(String msg) { super(msg); }
}
