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

@Slf4j
@Component
public class AccountConfirmationEmailService {

    // ---- SMTP configuration ----
    @Value("${mail.host}") private String host;
    @Value("${mail.port}") private int port;
    @Value("${mail.username}") private String username;
    @Value("${mail.password}") private String password;
    @Value("${mail.properties.mail.smtp.auth:true}") private boolean smtpAuth;
    @Value("${mail.properties.mail.smtp.starttls.enable:true}") private boolean startTls;

    // ---- Brand / assets ----
    @Value("${application.brand.name:Diana Global}")
    private String brandName;

    // Using an external URL to avoid inline attachments (CID) in Gmail
    @Value("${mail.logo.url:https://andescore-landingpage.vercel.app/AndesCore.jpg}")
    private String logoUrl;

    private JavaMailSender mailSender;

    // ---- Theme tokens (easy to override keeping OCP) ----
    protected String bgHeaderStart() { return "#0a2239"; }
    protected String bgHeaderEnd()   { return "#0e4b68"; }
    protected String textPrimary()   { return "#111827"; }  // dark neutral (previous color)
    protected String textMuted()     { return "#6b7280"; }
    protected String buttonBg()      { return "#111827"; }
    protected String buttonText()    { return "#ffffff"; }

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

    /** minutes must be INT. */
    public void send(String toEmail, String toName, String link, int minutes) {
        try {
            String subject = subject();
            String html = buildHtml(toName, link, minutes);

            MimeMessage message = mailSender.createMimeMessage();
            // multipart=false because we don't attach inline images
            MimeMessageHelper helper = new MimeMessageHelper(message, false, StandardCharsets.UTF_8.name());
            helper.setTo(toEmail);
            helper.setSubject(subject);
            helper.setText(html, true);
            try { helper.setFrom(username, brandName); } catch (Exception ignore) { helper.setFrom(username); }

            mailSender.send(message);
            log.info("Account confirmation e-mail sent to {}", toEmail);
        } catch (Exception e) {
            log.error("Error sending account confirmation e-mail to {}: {}", toEmail, e.getMessage(), e);
            throw new RuntimeException("Failed to send account confirmation e-mail", e);
        }
    }

    // -------- Template (OCP: protected hooks for easy customization) --------
    protected String subject() {
        return brandName + " – Confirm your account";
    }

    protected String headerHtml() {
        // Header with logo (left) + brand (right). No subtitle line.
        return """
            <div style="background:linear-gradient(135deg,%s,%s);color:#fff;padding:16px 20px;">
              <table width="100%%" cellspacing="0" cellpadding="0" style="border-collapse:collapse">
                <tr>
                  <td style="width:64px;vertical-align:middle;">
                    <img src="%s" alt="%s" width="56" style="display:block;border-radius:6px;">
                  </td>
                  <td style="text-align:right;vertical-align:middle;">
                    <div style="font-weight:700;font-size:18px;line-height:1;"><strong>%s</strong></div>
                  </td>
                </tr>
              </table>
            </div>
            """.formatted(bgHeaderStart(), bgHeaderEnd(), logoUrl, escapeHtml(brandName), escapeHtml(brandName));
    }

    protected String bodyHtml(String safeName, String link, int minutes) {
        // All text uses previous neutral color (no purple)
        return """
            <div style="padding:24px;color:%s">
              <p style="font-size:16px;margin:0 0 12px">Hello, <strong>%s</strong>!</p>
              <p style="margin:0 0 12px;line-height:1.55">
                Thanks for signing up to <strong>%s</strong>. Please confirm your account:
              </p>
              <p style="margin:20px 0">
                <a href="%s" target="_blank" rel="noopener noreferrer"
                   style="display:inline-block;padding:12px 18px;border-radius:6px;text-decoration:none;
                          background:%s;color:%s;font-weight:600">
                  Confirm my account
                </a>
              </p>
              <p style="margin:0 0 12px;line-height:1.55">
                For your security, this link expires in <strong>%d minutes</strong> and can be used only once.
              </p>
              <p style="font-size:12px;color:%s;margin-top:16px;word-break:break-all">
                If the button doesn’t work, copy and paste this link into your browser:<br>%s
              </p>
            </div>
            """.formatted(textPrimary(), safeName, escapeHtml(brandName), link, buttonBg(), buttonText(), minutes, textMuted(), link);
    }

    protected String footerHtml() {
        int year = Year.now().getValue();
        return """
            <div style="background:linear-gradient(135deg,%s,%s);color:#fff;
                        padding:6px 18px;text-align:center;font-size:14px;line-height:1;">
              <span role="img" aria-label="raio"
                    style="color:#ffd200;font-size:22px;vertical-align:middle;">&#x26A1;&#xFE0E;</span>
              <span style="vertical-align:middle;">© %d · Powered by <strong>Andes Core Software</strong></span>
            </div>
            """.formatted(bgHeaderStart(), bgHeaderEnd(), year);
    }

    protected String buildHtml(String name, String link, int minutes) {
        String safeName = (name == null || name.isBlank()) ? "there" : escapeHtml(name);
        String title = subject();

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
                %s
                %s
                %s
              </div>
            </body>
            </html>
            """.formatted(
                escapeHtml(title),
                headerHtml(),
                bodyHtml(safeName, link, minutes),
                footerHtml()
        );
    }

    // -------- Utils --------
    private static String escapeHtml(String s) {
        return s.replace("&","&amp;")
                .replace("<","&lt;")
                .replace(">","&gt;")
                .replace("\"","&quot;")
                .replace("'","&#x27;");
    }
}
