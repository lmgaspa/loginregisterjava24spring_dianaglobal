// src/main/java/com/dianaglobal/loginregister/adapter/out/mail/AccountConfirmationEmailService.java
package com.dianaglobal.loginregister.adapter.out.mail;

import jakarta.annotation.PostConstruct;
import jakarta.mail.internet.MimeMessage;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.util.Properties;

@Slf4j
@Service
public class AccountConfirmationEmailService {

    // ---- SMTP from env/application.yml (mesmo que PasswordResetEmailService) ----
    @Value("${mail.host}") private String host;
    @Value("${mail.port}") private int port;
    @Value("${mail.username}") private String username;
    @Value("${mail.password}") private String password;
    @Value("${mail.properties.mail.smtp.auth:true}") private boolean smtpAuth;
    @Value("${mail.properties.mail.smtp.starttls.enable:true}") private boolean startTls;

    // Branding
    @Value("${application.brand.name:Diana Global}")
    private String brandName;

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
        // props.put("mail.debug", "true");

        this.mailSender = impl;
        log.info("AccountConfirmationEmailService initialized with host={} port={}", host, port);
    }

    /**
     * Sends the account confirmation e-mail with the link and expiration.
     * @param to recipient e-mail
     * @param name recipient name (nullable)
     * @param link confirmation URL
     * @param minutes link validity in minutes (e.g. 45)
     */
    public void send(String to, String name, String link, int minutes) {
        try {
            String subject = brandName + " – Confirm your account";
            String html = buildHtml(name, link, minutes);

            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(
                    message,
                    MimeMessageHelper.MULTIPART_MODE_MIXED_RELATED,
                    StandardCharsets.UTF_8.name()
            );
            helper.setTo(to);
            helper.setSubject(subject);
            helper.setText(html, true);
            // helper.setFrom(username, brandName); // se seu provedor exigir

            mailSender.send(message);
            log.info("Sent account confirmation email to {}", to);
        } catch (Exception e) {
            log.error("Error sending account confirmation e-mail to {}: {}", to, e.getMessage(), e);
            throw new RuntimeException("Failed to send account confirmation e-mail", e);
        }
    }

    // ---- HTML (placeholders corretos) ----
    private String buildHtml(String name, String link, int minutes) {
        String safeName = (name == null || name.isBlank()) ? "there" : escapeHtml(name);
        String title = brandName + " – Confirm your account";

        return """
            <!doctype html>
            <html lang="en">
            <head>
              <meta charset="utf-8">
              <meta name="viewport" content="width=device-width"/>
              <title>%s</title>
              <style>
                body{background:#f3f4f6;margin:0;padding:24px;font-family:Arial,Helvetica,sans-serif;color:#111827;}
                .card{max-width:640px;margin:0 auto;background:#ffffff;border-radius:8px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.08);}
                .header{background:#111827;color:#fff;padding:16px 24px;font-size:18px;font-weight:600}
                .content{padding:24px}
                .greet{font-size:16px;margin:0 0 12px}
                .p{margin:0 0 12px;line-height:1.55}
                .btn{display:inline-block;padding:12px 18px;border-radius:6px;text-decoration:none;background:#111827;color:#fff;font-weight:600}
                .muted{font-size:12px;color:#6b7280;margin-top:16px}
                .footer{padding:12px 24px;color:#6b7280;font-size:12px;border-top:1px solid #e5e7eb}
                a.btn:link,a.btn:visited{color:#fff}
                @media (prefers-color-scheme: dark){
                  body{background:#0b0b0c;color:#e5e7eb}
                  .card{background:#16181d;box-shadow:none;border:1px solid #22252b}
                  .header{background:#0b0b0c}
                  .btn{background:#e5e7eb;color:#0b0b0c}
                  .footer{border-top-color:#22252b;color:#9ca3af}
                }
              </style>
            </head>
            <body>
              <div class="card">
                <div class="header">%s</div>
                <div class="content">
                  <p class="greet">Hi %s,</p>
                  <p class="p">Welcome to %s!</p>
                  <p class="p">Please confirm your account by clicking the button below. The link expires in <strong>%d minutes</strong>.</p>
                  <p style="margin:20px 0">
                    <a class="btn" href="%s" target="_blank" rel="noopener noreferrer">Confirm my account</a>
                  </p>
                  <p class="p">If you didn’t create an account, you can safely ignore this e-mail.</p>
                  <p class="muted">If the button does not work, copy and paste this link into your browser:<br>%s</p>
                </div>
                <div class="footer">
                  © %s. All rights reserved.
                </div>
              </div>
            </body>
            </html>
            """.formatted(
                title,          // <title>
                title,          // header
                safeName,       // greeting name
                escapeHtml(brandName), // welcome line
                minutes,        // %d minutes (int)
                link,           // button href
                link,           // plain link
                escapeHtml(brandName)  // footer
        );
    }

    private static String escapeHtml(String s) {
        return s.replace("&","&amp;")
                .replace("<","&lt;")
                .replace(">","&gt;")
                .replace("\"","&quot;")
                .replace("'","&#x27;");
    }
}
