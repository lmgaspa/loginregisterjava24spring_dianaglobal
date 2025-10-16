// src/main/java/com/dianaglobal/loginregister/adapter/out/mail/PasswordResetEmailService.java
package com.dianaglobal.loginregister.adapter.out.mail;

import com.dianaglobal.loginregister.config.MailConfig.MailBranding;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.time.Year;

@Slf4j
@Service
@RequiredArgsConstructor
public class PasswordResetEmailService {

    private final JavaMailSender mailSender;
    private final MailBranding branding;

    @Value("${mail.username}") private String fromAddress;

    public void sendPasswordReset(String to, String name, String link, int minutes) {
        try {
            String subject = branding.brandName() + " – Password Reset";
            String html = buildHtml(name, link, minutes);

            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, false, StandardCharsets.UTF_8.name());
            helper.setTo(to);
            helper.setSubject(subject);
            helper.setText(html, true);
            try { helper.setFrom(fromAddress, branding.brandName()); } catch (Exception ignore) { helper.setFrom(fromAddress); }

            mailSender.send(message);
            log.info("Password reset e-mail sent to {}", to);
        } catch (Exception e) {
            log.error("Error sending password reset e-mail to {}: {}", to, e.getMessage(), e);
            throw new RuntimeException("Failed to send password reset e-mail", e);
        }
    }

    private String buildHtml(String name, String link, int minutes) {
        String safeName = (name == null || name.isBlank()) ? "customer" : escapeHtml(name);
        int year = Year.now().getValue();
        String subtitle = "Password reset";
        String logoUrl = branding.safeLogoUrl();

        return """
            <!doctype html>
            <html lang="en">
            <head>
              <meta charset="utf-8">
              <meta name="viewport" content="width=device-width"/>
              <title>%s – Password Reset</title>
              <style>img{display:block}</style>
            </head>
            <body style="font-family:Arial,Helvetica,sans-serif;background:#f6f7f9;padding:24px;margin:0;color:#111827;">
              <div style="max-width:640px;margin:0 auto;background:#fff;border:1px solid #eee;border-radius:12px;overflow:hidden">
                <div style="background:linear-gradient(135deg,#0a2239,#0e4b68);color:#fff;padding:16px 20px;">
                  <table role="presentation" width="100%%" cellspacing="0" cellpadding="0" style="border-collapse:collapse">
                    <tr>
                      <td style="width:64px;vertical-align:middle;">
                        <img src="%s" alt="%s" width="56" height="56" style="display:block;border-radius:6px;width:56px;height:56px;outline:none;border:none;text-decoration:none;-ms-interpolation-mode:bicubic;">
                      </td>
                      <td style="text-align:right;vertical-align:middle;">
                        <div style="font-weight:700;font-size:18px;line-height:1;"><strong>%s</strong></div>
                        <div style="height:6px;line-height:6px;font-size:0;">&nbsp;</div>
                        <div style="opacity:.9;font-size:12px;line-height:1.2;margin-top:4px;">%s</div>
                      </td>
                    </tr>
                  </table>
                </div>
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
                       style="display:inline-block;padding:12px 18px;border-radius:8px;text-decoration:none;background:#111827;color:#fff;font-weight:600;font-size:14px;">
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
                <div style="background:linear-gradient(135deg,#0a2239,#0e4b68);color:#fff;
                            padding:6px 18px;text-align:center;font-size:14px;line-height:1;">
                  <span role="img" aria-label="lightning"
                        style="color:#ffd200;font-size:22px;vertical-align:middle;">&#x26A1;&#xFE0E;</span>
                  <span style="vertical-align:middle;">&nbsp;© %d · Powered by <strong>AndesCore Software</strong>&#8203;</span>
                </div>
              </div>
            </body>
            </html>
            """.formatted(
                branding.brandName(), // title
                logoUrl,              // img src
                branding.brandName(), // alt
                branding.brandName(), // brand text
                subtitle,             // subtitle line
                safeName,
                branding.brandName(),
                minutes,
                link,
                link,
                year
        );
    }

    private static String escapeHtml(String s) {
        return s == null ? "" : s.replace("&","&amp;")
                .replace("<","&lt;").replace(">","&gt;")
                .replace("\"","&quot;").replace("'","&#x27;");
    }
}
