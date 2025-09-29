package com.dianaglobal.loginregister.adapter.out.mail;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class AccountConfirmationEmailService {

    private final JavaMailSender mailSender;

    @Value("${application.brand.name:Your App}")
    private String brandName;

    public void send(String toEmail, String toName, String link, int minutes) {
        // build and send message here (omitted for brevity)
        log.info("Sent account confirmation to {} ({} min)", toEmail, minutes);
        String subject = brandName + " – Confirm your account";
        String body = buildBody(toName, link, minutes);
        SimpleMailMessage msg = new SimpleMailMessage();
        msg.setTo(toEmail);
        msg.setSubject(subject);
        msg.setText(body);

        mailSender.send(msg);
        log.info("Sent account confirmation email to {}", toEmail);
    }

    private String buildBody(String name, String link, int minutes) {
        return """
                Hi %s,

                Welcome to %s!

                Please confirm your account by clicking the link below:
                %s

                For your security, this link expires in %d minutes and can be used only once.
                If you didn’t create an account, you can safely ignore this message.

                Thanks,
                %s Team
                """.formatted(
                name == null || name.isBlank() ? "there" : name,
                brandName, link, minutes, brandName
        );
    }
}
