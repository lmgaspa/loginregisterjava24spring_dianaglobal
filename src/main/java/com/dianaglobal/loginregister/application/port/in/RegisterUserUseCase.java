package com.dianaglobal.loginregister.application.port.in;

public interface RegisterUserUseCase {
    void register(String name, String email, String password);
    void registerOauthUser(String name, String email, String googleSub);
}


