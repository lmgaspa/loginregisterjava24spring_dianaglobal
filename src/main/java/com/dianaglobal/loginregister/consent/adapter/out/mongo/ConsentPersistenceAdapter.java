package com.dianaglobal.loginregister.consent.adapter.out.mongo;

import com.dianaglobal.loginregister.consent.domain.CookieConsent;
import com.dianaglobal.loginregister.consent.port.out.ListConsentLogsPort;
import com.dianaglobal.loginregister.consent.port.out.SaveConsentLogPort;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.UUID;

@Component
@RequiredArgsConstructor
public class ConsentPersistenceAdapter implements SaveConsentLogPort, ListConsentLogsPort {

    private final CookieConsentMongoRepository repo;

    @Override
    public void save(CookieConsent consent) {
        repo.save(CookieConsentMongoMapper.toDocument(consent));
    }

    @Override
    public List<CookieConsent> findByUserId(UUID userId) {
        return repo.findAllByUserId(userId).stream()
                .map(CookieConsentMongoMapper::toDomain)
                .toList();
    }
}
