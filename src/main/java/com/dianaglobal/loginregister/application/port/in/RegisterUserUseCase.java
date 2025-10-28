// src/main/java/com/dianaglobal/loginregister/application/port/in/RegisterUserUseCase.java
package com.dianaglobal.loginregister.application.port.in;

import com.dianaglobal.loginregister.domain.model.User;

public interface RegisterUserUseCase {
    void register(String name, String email, String password);

    /** Cria (ou garante) usuário de OAuth e retorna a entidade persistida. */
    User registerOauthUser(String name, String email, String googleSub);
}
