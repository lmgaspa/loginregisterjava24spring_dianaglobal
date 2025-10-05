package com.dianaglobal.loginregister.consent.port.out;

import com.dianaglobal.loginregister.consent.domain.CookieConsent;
import java.util.*;

public interface ListConsentLogsPort {
    List<CookieConsent> findByUserId(UUID userId);
}
