// src/main/java/com/dianaglobal/loginregister/adapter/out/persistence/entity/UserEntity.java
package com.dianaglobal.loginregister.adapter.out.persistence.entity;

import com.dianaglobal.loginregister.domain.model.User;
import lombok.*;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.Field; // ✅ import correto

import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Document(collection = "users")
public class UserEntity {

    @Id
    private UUID id;

    private String name;

    @Indexed(unique = true)
    private String email;

    private String password;

    @Builder.Default
    private boolean emailConfirmed = false;

    // ✅ novos campos
    @Builder.Default
    @Field("auth_provider")
    private String authProvider = "LOCAL"; // default para novos registros locais

    @Builder.Default
    @Field("password_set")
    private boolean passwordSet = false;   // default para novos registros

    // ---------- Mapeamentos domínio <-> entidade ----------

    public static UserEntity fromDomain(User d) {
        if (d == null) return null;
        return UserEntity.builder()
                .id(d.getId())
                .name(d.getName())
                .email(d.getEmail())
                .password(d.getPassword())
                .emailConfirmed(d.isEmailConfirmed())
                // ✅ copiar campos novos do domínio
                .authProvider(d.getAuthProvider())
                .passwordSet(d.isPasswordSet())
                .build();
    }

    public static User toDomain(UserEntity e) {
        if (e == null) return null;
        return User.builder()
                .id(e.getId())
                .name(e.getName())
                .email(e.getEmail())
                .password(e.getPassword())
                .emailConfirmed(e.isEmailConfirmed())
                // ✅ copiar campos novos para o domínio
                .authProvider(e.getAuthProvider())
                .passwordSet(e.isPasswordSet())
                .build();
    }
}
