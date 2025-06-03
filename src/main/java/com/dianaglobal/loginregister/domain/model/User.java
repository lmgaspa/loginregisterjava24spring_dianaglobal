package com.dianaglobal.loginregister.domain.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;

import java.util.UUID;

@Getter
@AllArgsConstructor
@Builder
public class User {
    private final UUID id;
    private final String email;
    private final String password;

    public User(String email, String password) {
        this.id = null;
        this.email = email;
        this.password = password;
    }
}


