// src/main/java/com/dianaglobal/loginregister/adapter/out/mail/AccountConfirmationEmailService.java
package com.dianaglobal.loginregister.adapter.out.mail;

import jakarta.annotation.PostConstruct;
import jakarta.mail.internet.MimeMessage;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.time.Year;
import java.util.Properties;
import java.util.UUID;

@Slf4j
@Component
public class AccountConfirmationEmailService {

    @Value("${mail.host}") private String host;
    @Value("${mail.port}") private int port;
    @Value("${mail.username}") private String username;
    @Value("${mail.password}") private String password;
    @Value("${mail.properties.mail.smtp.auth:true}") private boolean smtpAuth;
    @Value("${mail.properties.mail.smtp.starttls.enable:true}") private boolean startTls;

    @Value("${application.brand.name:Diana Global}")
    private String brandName;

    @Value("${application.frontend.url:https://www.dianaglobal.com.br}")
    private String frontendBaseUrl;

    @Value("${mail.logo.url:https://andescore-landingpage.vercel.app/AndesCore.jpg}")
    private String logoUrl;

    private JavaMailSender mailSender;

    @PostConstruct
    void init() {
        JavaMailSenderImpl impl = new JavaMailSenderImpl();
        impl.setHost(host);
        impl.setPort(port);
        impl.setUsername(username);
        impl.setPassword(password);
        impl.setDefaultEncoding(StandardCharsets.UTF_8.name());

        Properties props = impl.getJavaMailProperties();
        props.put("mail.smtp.auth", Boolean.toString(smtpAuth));
        props.put("mail.smtp.starttls.enable", Boolean.toString(startTls));
        this.mailSender = impl;

        log.info("AccountConfirmationEmailService initialized with host={} port={}", host, port);
    }

    /** Assinatura esperada pelo AccountConfirmationService */
    public void send(String toEmail, String name, String confirmLink, int minutes) {
        final String subject = "Confirm your e-mail";
        final String html = buildHtml(name, confirmLink, minutes);
        sendHtml(toEmail, subject, html);
    }

    private void sendHtml(String toEmail, String subject, String html) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, false, StandardCharsets.UTF_8.name());
            helper.setTo(toEmail);
            helper.setSubject(subject);
            helper.setText(html, true);
            try { helper.setFrom(username, brandName); } catch (Exception ignore) { helper.setFrom(username); }
            mailSender.send(message);
            log.info("[MAIL] Sent '{}' to {}", subject, toEmail);
        } catch (Exception e) {
            log.error("[MAIL] Error sending '{}' to {}: {}", subject, toEmail, e.getMessage(), e);
        }
    }

    private String buildHtml(String name, String confirmLink, int minutes) {
        String safeName = (name == null || name.isBlank()) ? "there" : escapeHtml(name);
        int year = Year.now().getValue();
        String msgId = UUID.randomUUID().toString(); // id opcional para rastreio

        return """
            <!doctype html>
            <html lang="en">
            <head>
              <meta charset="utf-8">
              <meta name="viewport" content="width=device-width"/>
              <title>Confirm your e-mail · %s</title>
            </head>
            <body style="font-family:Arial,Helvetica,sans-serif;background:#f6f7f9;padding:24px">
              <div style="max-width:640px;margin:0 auto;background:#fff;border:1px solid #eee;border-radius:12px;overflow:hidden">

                <!-- HEADER -->
                <div style="background:linear-gradient(135deg,#0a2239,#0e4b68);color:#fff;padding:16px 20px;">
                  <table width="100%%" cellspacing="0" cellpadding="0" style="border-collapse:collapse">
                    <tr>
                      <td style="width:64px;vertical-align:middle;">
                        <img src="%s" alt="%s" width="56" style="display:block;border-radius:6px;">
                      </td>
                      <td style="text-align:right;vertical-align:middle;">
                        <div style="font-weight:700;font-size:18px;line-height:1;"><strong>%s</strong></div>
                        <div style="height:6px;line-height:6px;font-size:0;">&nbsp;</div>
                        <div style="opacity:.9;font-size:12px;line-height:1.2;margin-top:4px;">Confirm your e-mail</div>
                      </td>
                    </tr>
                  </table>
                </div>

                <!-- CONTENT -->
                <div style="padding:24px">
                  <p style="font-size:16px;margin:0 0 12px">Hello, <strong>%s</strong>!</p>
                  <p style="margin:0 0 12px;line-height:1.55">
                    Thanks for signing up. To finish creating your account, please confirm your e-mail address.
                    This link expires in <strong>%d minutes</strong>.
                  </p>

                  <p style="margin:20px 0">
                    <a href="%s" target="_blank" rel="noopener noreferrer"
                       style="display:inline-block;padding:12px 18px;border-radius:6px;text-decoration:none;
                              background:#111827;color:#fff;font-weight:600">
                      Confirm e-mail
                    </a>
                  </p>

                  <p style="margin:0 0 12px;line-height:1.55;color:#374151">
                    If you didn’t request this, please ignore this message or contact support.
                  </p>
                </div>

                <!-- FOOTER -->
                <div style="background:linear-gradient(135deg,#0a2239,#0e4b68);color:#fff;
                            padding:6px 18px;text-align:center;font-size:14px;line-height:1;">
                  <span role="img" aria-label="lightning"
                        style="color:#ffd200;font-size:22px;vertical-align:middle;">&#x26A1;&#xFE0E;</span>
                  <span style="vertical-align:middle;">© %d · Powered by <strong>AndesCore Software</strong> · id:%s</span>
                </div>
              </div>
            </body>
            </html>
            """.formatted(
                brandName,       // <title> brand
                logoUrl,         // img src
                brandName,       // img alt
                brandName,       // header brand
                safeName,        // Hello, X
                minutes,         // expires in X minutes
                confirmLink,     // CTA link
                year,            // © year
                msgId            // footer id
        );
    }

    private static String escapeHtml(String s) {
        return s == null ? "" : s.replace("&","&amp;")
                .replace("<","&lt;")
                .replace(">","&gt;")
                .replace("\"","&quot;")
                .replace("'","&#x27;");
    }
}
