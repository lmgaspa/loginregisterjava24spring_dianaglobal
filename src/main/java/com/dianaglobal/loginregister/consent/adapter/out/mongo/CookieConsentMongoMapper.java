package com.dianaglobal.loginregister.consent.adapter.out.mongo;

import com.dianaglobal.loginregister.consent.domain.ConsentCategories;
import com.dianaglobal.loginregister.consent.domain.CookieConsent;

public final class CookieConsentMongoMapper {
    private CookieConsentMongoMapper(){}

    public static CookieConsentDocument toDocument(CookieConsent d) {
        CookieConsentDocument doc = new CookieConsentDocument();
        doc.setId(d.getId());
        doc.setUserId(d.getUserId());
        doc.setVersion(d.getVersion());
        doc.setDecision(d.getDecision());
        doc.setAnalytics(d.getCategories().isAnalytics());
        doc.setMarketing(d.getCategories().isMarketing());
        doc.setIp(d.getIp());
        doc.setUserAgent(d.getUserAgent());
        doc.setCreatedAt(d.getCreatedAt());
        return doc;
    }

    public static CookieConsent toDomain(CookieConsentDocument doc) {
        return CookieConsent.builder()
                .id(doc.getId())
                .userId(doc.getUserId())
                .version(doc.getVersion())
                .decision(doc.getDecision())
                .categories(new ConsentCategories(doc.isAnalytics(), doc.isMarketing()))
                .ip(doc.getIp())
                .userAgent(doc.getUserAgent())
                .createdAt(doc.getCreatedAt())
                .build();
    }
}
