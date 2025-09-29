// src/main/java/com/dianaglobal/loginregister/adapter/out/persistence/entity/UserEntity.java
package com.dianaglobal.loginregister.adapter.out.persistence.entity;

import com.dianaglobal.loginregister.domain.model.User;
import lombok.*;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

import java.util.UUID;

@Document(collection = "users")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserEntity {

    @Id
    private UUID id;

    @Indexed(unique = true)
    private String email;

    private String password;
    private String name;

    public User toDomain() {
        // keep the persisted ID, never generate a new one here
        return new User(this.id, this.name, this.email, this.password);
    }

    public static UserEntity fromDomain(User user) {
        return UserEntity.builder()
                .id(user.getId())
                .email(user.getEmail())
                .password(user.getPassword())
                .name(user.getName())
                .build();
    }
}
