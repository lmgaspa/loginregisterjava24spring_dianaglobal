// src/main/java/com/dianaglobal/loginregister/application/service/exception/EmailAlreadyUsedException.java
package com.dianaglobal.loginregister.application.service.exception;

public class EmailAlreadyUsedException extends RuntimeException {
    public EmailAlreadyUsedException(String email) {
        super("E-mail already in use: " + email);
    }
}
