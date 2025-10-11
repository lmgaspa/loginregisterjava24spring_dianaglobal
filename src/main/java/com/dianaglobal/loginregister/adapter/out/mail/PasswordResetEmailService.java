// src/main/java/com/dianaglobal/loginregister/adapter/out/mail/PasswordResetEmailService.java
package com.dianaglobal.loginregister.adapter.out.mail;

import jakarta.annotation.PostConstruct;
import jakarta.mail.internet.MimeMessage;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.mail.javamail.MimeMessageHelper;

import java.nio.charset.StandardCharsets;
import java.time.Year;
import java.util.Properties;

@Slf4j
@Service
public class PasswordResetEmailService {

    // ---- SMTP from env/application.yml ----
    @Value("${mail.host}") private String host;
    @Value("${mail.port}") private int port;
    @Value("${mail.username}") private String username;
    @Value("${mail.password}") private String password;
    @Value("${mail.properties.mail.smtp.auth:true}") private boolean smtpAuth;
    @Value("${mail.properties.mail.smtp.starttls.enable:true}") private boolean startTls;

    // ---- Branding ----
    @Value("${application.brand.name:Diana Global}")
    private String appName;

    /** Caminho da logo no classpath (igual ao PixEmailService). */
    @Value("${mail.logo.classpath:static/images/logo-andescore.jpeg}")
    private String logoClasspath;

    private JavaMailSender mailSender;

    private static final String EMAIL_TITLE = "Diana Global – Password Reset";

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
        // props.put("mail.debug", "true"); // opcional

        this.mailSender = impl;
        log.info("PasswordResetEmailService initialized with host={} port={}", host, port);
    }

    /**
     * Sends the password reset e-mail with the link and expiration.
     * @param to user's e-mail
     * @param name user's name (may be null)
     * @param link full reset URL (e.g. https://.../reset-password?token=...)
     * @param minutes link validity in minutes (e.g. 45)
     */
    public void sendPasswordReset(String to, String name, String link, int minutes) {
        try {
            String subject = EMAIL_TITLE;
            String html = buildHtml(name, link, minutes);

            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(
                    message,
                    true, // multipart para permitir inline image
                    StandardCharsets.UTF_8.name()
            );
            helper.setTo(to);
            helper.setSubject(subject);
            helper.setText(html, true);

            // From opcional (alguns provedores exigem apenas o e-mail, sem personal name)
            try {
                helper.setFrom(username, appName);
            } catch (Exception ignore) {
                helper.setFrom(username);
            }

            // Inline logo (CID igual ao PixEmailService)
            ClassPathResource logoRes = new ClassPathResource(logoClasspath);
            if (logoRes.exists()) {
                helper.addInline("logoAndesCore", logoRes);
            } else {
                log.warn("Logo não encontrada em {}", logoClasspath);
            }

            mailSender.send(message);
            log.info("Password reset e-mail sent to {}", to);
        } catch (Exception e) {
            log.error("Error sending password reset e-mail to {}: {}", to, e.getMessage(), e);
            throw new RuntimeException("Failed to send password reset e-mail", e);
        }
    }

    // ---- E-mail HTML com mesmo header/footer do Pix ----
    private String buildHtml(String name, String link, int minutes) {
        String safeName = (name == null || name.isBlank()) ? "customer" : escapeHtml(name);
        int year = Year.now().getValue();
        String subtitle = "Password reset";

        return """
            <!doctype html>
            <html lang="en">
            <head>
              <meta charset="utf-8">
              <meta name="viewport" content="width=device-width"/>
              <title>%s</title>
            </head>
            <body style="font-family:Arial,Helvetica,sans-serif;background:#f6f7f9;padding:24px">
              <div style="max-width:640px;margin:0 auto;background:#fff;border:1px solid #eee;border-radius:12px;overflow:hidden">

                <!-- HEADER (mesmo do PixEmailService) -->
                <div style="background:linear-gradient(135deg,#0a2239,#0e4b68);color:#fff;padding:16px 20px;">
                  <table width="100%%" cellspacing="0" cellpadding="0" style="border-collapse:collapse">
                    <tr>
                      <td style="width:64px;vertical-align:middle;">
                        <img src="cid:logoAndesCore" alt="AndesCore Software" width="56" style="display:block;border-radius:6px;">
                      </td>
                      <td style="text-align:right;vertical-align:middle;">
                        <div style="font-weight:700;font-size:18px;line-height:1;"><strong>AndesCore Software</strong></div>
                        <div style="height:6px;line-height:6px;font-size:0;">&nbsp;</div>
                        <div style="opacity:.9;font-size:12px;line-height:1.2;margin-top:4px;">%s</div>
                      </td>
                    </tr>
                  </table>
                </div>

                <!-- CONTEÚDO -->
                <div style="padding:24px">
                  <p style="font-size:16px;margin:0 0 12px">Hello, <strong>%s</strong>!</p>
                  <p style="margin:0 0 12px;line-height:1.55">
                    We received a request to reset your password for <strong>%s</strong>.
                  </p>
                  <p style="margin:0 0 12px;line-height:1.55">
                    To continue, click the button below. The link expires in <strong>%d minutes</strong>.
                  </p>
                  <p style="margin:20px 0">
                    <a href="%s" target="_blank" rel="noopener noreferrer"
                       style="display:inline-block;padding:12px 18px;border-radius:6px;text-decoration:none;
                              background:#111827;color:#fff;font-weight:600">
                      Reset my password
                    </a>
                  </p>
                  <p style="margin:0 0 12px;line-height:1.55">
                    If you did not request this change, you can safely ignore this e-mail.
                  </p>
                  <p style="font-size:12px;color:#6b7280;margin-top:16px;word-break:break-all">
                    If the button doesn’t work, copy and paste this link into your browser:<br>%s
                  </p>
                </div>

                <!-- FOOTER (mesmo do PixEmailService) -->
                <div style="background:linear-gradient(135deg,#0a2239,#0e4b68);color:#fff;
                            padding:6px 18px;text-align:center;font-size:14px;line-height:1;">
                  <span role="img" aria-label="raio"
                        style="color:#ffd200;font-size:22px;vertical-align:middle;">&#x26A1;&#xFE0E;</span>
                  <span style="vertical-align:middle;">© %d · Powered by <strong>Andes Core Software</strong></span>
                </div>
              </div>
            </body>
            </html>
            """.formatted(
                EMAIL_TITLE,     // <title>
                subtitle,        // header subtitle
                safeName,        // greeting
                appName,         // app name in body
                minutes,
                link,
                link,
                year
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
