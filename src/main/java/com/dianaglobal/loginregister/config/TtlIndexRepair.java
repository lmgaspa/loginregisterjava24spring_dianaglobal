// src/main/java/.../config/TtlIndexRepair.java
package com.dianaglobal.loginregister.config;

import com.dianaglobal.loginregister.adapter.out.persistence.entity.AccountConfirmationTokenEntity;
import com.dianaglobal.loginregister.adapter.out.persistence.entity.PasswordResetTokenEntity;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.data.domain.Sort;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.index.Index;
import org.springframework.stereotype.Component;

import java.time.Duration;

@Component
@RequiredArgsConstructor
public class TtlIndexRepair implements ApplicationRunner {

    private final MongoTemplate mongo;

    @Override
    public void run(ApplicationArguments args) {
        // password_reset_tokens
        var prOps = mongo.indexOps(PasswordResetTokenEntity.class);
        prOps.getIndexInfo().stream()
                .filter(i -> "expiresAt".equals(i.getName()))
                .findFirst()
                .ifPresent(i -> prOps.dropIndex("expiresAt"));
        prOps.ensureIndex(new Index().on("expiresAt", Sort.Direction.ASC)
                .named("password_reset_expires_ttl")
                .expire(Duration.ZERO));

        // account_confirmation_tokens (se existir)
        var acOps = mongo.indexOps(AccountConfirmationTokenEntity.class);
        acOps.getIndexInfo().stream()
                .filter(i -> "expiresAt".equals(i.getName()))
                .findFirst()
                .ifPresent(i -> acOps.dropIndex("expiresAt"));
        acOps.ensureIndex(new Index().on("expiresAt", Sort.Direction.ASC)
                .named("account_confirm_expires_ttl")
                .expire(Duration.ZERO));
    }
}
