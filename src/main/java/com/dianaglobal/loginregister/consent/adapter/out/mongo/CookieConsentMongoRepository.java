package com.dianaglobal.loginregister.consent.adapter.out.mongo;

import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.List;
import java.util.UUID;

public interface CookieConsentMongoRepository extends MongoRepository<CookieConsentDocument, UUID> {
    List<CookieConsentDocument> findAllByUserId(UUID userId);
}
