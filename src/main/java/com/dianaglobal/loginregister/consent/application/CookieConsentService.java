package com.dianaglobal.loginregister.consent.application;

import com.dianaglobal.loginregister.consent.domain.CookieConsent;
import com.dianaglobal.loginregister.consent.port.in.LogConsentUseCase;
import com.dianaglobal.loginregister.consent.port.out.SaveConsentLogPort;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service @RequiredArgsConstructor
public class CookieConsentService implements LogConsentUseCase {
    private final SaveConsentLogPort savePort;

    @Transactional
    @Override public void log(CookieConsent consent) {
        // regras de domínio poderiam entrar aqui
        savePort.save(consent);
    }
}
