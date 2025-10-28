// src/main/java/com/dianaglobal/loginregister/domain/model/User.java
package com.dianaglobal.loginregister.domain.model;

import lombok.*;

import java.util.UUID;

// src/main/java/com/dianaglobal/loginregister/domain/model/User.java
@Getter @Setter
@NoArgsConstructor @AllArgsConstructor
@Builder
public class User {
    private UUID id;
    private String name;
    private String email;
    private String password;          // pode ficar null
    private boolean emailConfirmed;

    // NOVOS:
    private String authProvider;      // "LOCAL" | "GOOGLE" | null
    private boolean passwordSet;      // true quando o usuário definiu senha conscientemente
}

//