// src/main/java/com/dianaglobal/loginregister/adapter/out/persistence/entity/UserEntity.java
package com.dianaglobal.loginregister.adapter.out.persistence.entity;

import com.dianaglobal.loginregister.domain.model.User;
import lombok.*;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

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

    public static UserEntity fromDomain(User d) {
        if (d == null) return null;
        return UserEntity.builder()
                .id(d.getId())
                .name(d.getName())
                .email(d.getEmail())
                .password(d.getPassword())
                .emailConfirmed(d.isEmailConfirmed())
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
                .build();
    }
}
