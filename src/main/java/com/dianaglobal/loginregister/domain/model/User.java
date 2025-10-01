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
    private boolean emailConfirmed;

    /** Novos campos para fluxos combinados (senha x OAuth). */
    private boolean passwordSet;      // true quando o usuário criou/definiu senha (registro por e-mail ou set posterior)
    private String authProvider;      // "GOOGLE" quando veio do OAuth (null para cadastro por senha)
    // Se quiser guardar o "sub" do Google, adicione também:
    // private String providerId;
}
