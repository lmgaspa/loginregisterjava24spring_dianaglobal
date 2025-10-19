// src/main/java/com/dianaglobal/loginregister/config/MongoTtlConfig.java
package com.dianaglobal.loginregister.config;

import com.dianaglobal.loginregister.adapter.out.persistence.entity.AccountConfirmationTokenEntity;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.event.EventListener;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.index.Index;
import org.springframework.data.mongodb.core.mapping.event.ContextRefreshedEvent;

@Configuration
public class MongoTtlConfig {

    private final MongoTemplate mongoTemplate;

    public MongoTtlConfig(MongoTemplate mongoTemplate) {
        this.mongoTemplate = mongoTemplate;
    }

    // Cria/atualiza índice TTL em expiresAt (expireAfter 0 segundos => expira na data do campo)
    @EventListener(ContextRefreshedEvent.class)
    public void ensureIndexes() {
        mongoTemplate.indexOps(AccountConfirmationTokenEntity.class)
                .ensureIndex(new Index().on("expiresAt", org.springframework.data.domain.Sort.Direction.ASC).expire(0));
    }
}
