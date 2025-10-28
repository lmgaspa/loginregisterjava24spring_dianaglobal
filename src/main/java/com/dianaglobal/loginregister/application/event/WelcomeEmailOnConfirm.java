// src/main/java/com/dianaglobal/loginregister/application/event/WelcomeEmailOnConfirm.java
package com.dianaglobal.loginregister.application.event;

import com.dianaglobal.loginregister.adapter.out.mail.WelcomeEmailService;
import com.dianaglobal.loginregister.domain.model.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class WelcomeEmailOnConfirm implements UserConfirmedListener {

    private final WelcomeEmailService welcomeEmailService;

    @Override
    public void onUserConfirmed(User user) {
        try {
            welcomeEmailService.send(user.getEmail(), user.getName());
            log.info("Welcome e-mail successfully sent to {}", user.getEmail());
        } catch (Exception e) {
            log.warn("Failed to send welcome e-mail to {}: {}", user.getEmail(), e.getMessage());
        }
    }
}
