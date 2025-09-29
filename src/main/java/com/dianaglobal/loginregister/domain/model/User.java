// src/main/java/com/dianaglobal/loginregister/domain/model/User.java
package com.dianaglobal.loginregister.domain.model;

import lombok.*;

import java.util.UUID;

@Getter @Setter
@NoArgsConstructor @AllArgsConstructor
@Builder
public class User {
    private UUID id;
    private String name;
    private String email;
    private String password;
    private boolean emailConfirmed; // definir UMA vez só
}
