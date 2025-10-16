package com.dianaglobal.loginregister.config;

import com.dianaglobal.loginregister.adapter.out.persistence.entity.AccountConfirmationTokenEntity;
import com.dianaglobal.loginregister.adapter.out.persistence.entity.ConfirmResendThrottleEntity;
import com.dianaglobal.loginregister.adapter.out.persistence.entity.EmailChangeTokenEntity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.domain.Sort;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.index.Index;

import jakarta.annotation.PostConstruct;
import java.time.Duration;

@Configuration
public class TtlIndexRepair {

    private static final Logger log = LoggerFactory.getLogger(TtlIndexRepair.class);
    private final MongoTemplate mongoTemplate;

    public TtlIndexRepair(MongoTemplate mongoTemplate) {
        this.mongoTemplate = mongoTemplate;
    }

    @PostConstruct
    public void ensureTtlIndexes() {
        // TTL diário para throttle: expira createdAt + 1 dia
        mongoTemplate.indexOps(ConfirmResendThrottleEntity.class)
                .ensureIndex(new Index().on("createdAt", Sort.Direction.ASC).expire(Duration.ofDays(1)));

        // TTL exato para tokens: expira exatamente em expiresAt
        mongoTemplate.indexOps(AccountConfirmationTokenEntity.class)
                .ensureIndex(new Index().on("expiresAt", Sort.Direction.ASC).expire(Duration.ZERO));

        log.info("[TTL] TTL indexes ensured for throttle and confirmation tokens");

        mongoTemplate.indexOps(EmailChangeTokenEntity.class)
                .ensureIndex(new Index().on("expiresAt", Sort.Direction.ASC).expire(Duration.ZERO));
    }
}
