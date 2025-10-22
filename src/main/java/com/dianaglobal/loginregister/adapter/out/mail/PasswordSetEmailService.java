// src/main/java/com/dianaglobal/loginregister/adapter/out/mail/PasswordSetEmailService.java
package com.dianaglobal.loginregister.adapter.out.mail;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.MailSendException;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessagePreparator;
import org.springframework.stereotype.Component;

import com.dianaglobal.loginregister.config.MailConfig;
import com.dianaglobal.loginregister.config.MailConfig.MailBranding;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;


@Slf4j
@Component
@RequiredArgsConstructor
public class PasswordSetEmailService {

    private final JavaMailSender mailSender;
    private final MailBranding branding;

    @Value("${mail.username}") private String fromAddress;

    /**
     * Sends an e-mail informing password creation/change.
     * @param toEmail recipient e-mail
     * @param name    user name (can be null/blank)
     * @param firstDefinition true = first password setup; false = password change
     */
    public void send(String toEmail, String name, boolean firstDefinition) {
        try {
            String subject = firstDefinition
                    ? "✅ Your password was created at " + branding.brandName()
                    : "🔐 Your " + branding.brandName() + " password was changed";

            String html = buildHtml(name, firstDefinition);

            MimeMessagePreparator preparator = MailConfig.createPreparator(toEmail, subject, html, fromAddress, branding.brandName());
            mailSender.send(preparator);
            
            log.info("Password {} e-mail sent to {}", (firstDefinition ? "creation" : "change"), toEmail);
        } catch (MailSendException e) {
            log.error("Error sending password {} e-mail to {}: {}", (firstDefinition ? "creation" : "change"), toEmail, e.getMessage(), e);
        }
    }

    public void sendFirstDefinition(String toEmail, String name) { send(toEmail, name, true); }
    public void sendChange(String toEmail, String name) { send(toEmail, name, false); }

    private String buildHtml(String name, boolean firstDefinition) {
        String safeName = (name == null || name.isBlank()) ? "there" : escapeHtml(name);

        String title = firstDefinition ? "Password created" : "Password changed";
        String lead  = firstDefinition ? "Your password has been successfully created "
                : "Your password has been successfully changed ";
        String sub   = firstDefinition
                ? "From now on, you can sign in using your e-mail and this password (besides Google Login)."
                : "If this change wasn't made by you, please reset your password immediately.";

        String actionHref = firstDefinition
                ? branding.frontendUrl() + "/login"
                : branding.frontendUrl() + "/forgot-password";
        String actionLabel = firstDefinition ? "Access your account" : "Reset your password";

        String advisory = firstDefinition
                ? "If you didn't request this, we recommend changing your password."
                : "Security tip: enable 2FA in your account settings when available.";

        String logoUrl = branding.safeLogoUrl();

        return """
            <!doctype html>
            <html lang="en">
            <head>
              <meta charset="utf-8">
              <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
              <title>%s · %s</title>
              <style>
                img{display:block}
                body{margin:0;padding:0;-webkit-text-size-adjust:100%%;-ms-text-size-adjust:100%%;}
                table{border-collapse:collapse;mso-table-lspace:0pt;mso-table-rspace:0pt;}
                td{border-collapse:collapse;}
                p{margin:0;padding:0;}
                a{text-decoration:none;}
              </style>
            </head>
            <body style="font-family:Arial,Helvetica,sans-serif;background:#f6f7f9;padding:24px">
              <div style="max-width:640px;margin:0 auto;background:#fff;border:1px solid #eee;border-radius:12px;overflow:hidden">
                <div style="background:linear-gradient(135deg,#0a2239,#0e4b68);color:#fff;padding:16px 20px;">
                  <table width="100%%" cellspacing="0" cellpadding="0" style="border-collapse:collapse">
                    <tr>
                      <td style="width:64px;vertical-align:middle;">
                        <img src="%s" alt="%s" width="56" style="display:block;border-radius:6px;">
                      </td>
                      <td style="text-align:right;vertical-align:middle;">
                        <div style="font-weight:700;font-size:18px;line-height:1;"><strong>%s</strong></div>
                        <div style="height:6px;line-height:6px;font-size:0;">&nbsp;</div>
                        <div style="opacity:.9;font-size:12px;line-height:1.2;margin-top:4px;">Account security notice</div>
                      </td>
                    </tr>
                  </table>
                </div>
                <div style="padding:24px">
                  <p style="font-size:16px;margin:0 0 12px">Hello, <strong>%s</strong>!</p>
                  <p style="margin:0 0 8px;line-height:1.55"><strong>%s</strong> at <strong>%s</strong>.</p>
                  <p style="margin:0 0 12px;line-height:1.55">%s</p>
                  <p style="margin:20px 0">
                    <a href="%s" target="_blank" rel="noopener noreferrer"
                       style="display:inline-block;padding:12px 18px;border-radius:6px;text-decoration:none;background:#111827;color:#fff;font-weight:600">
                      %s
                    </a>
                  </p>
                  <p style="margin:0 0 12px;line-height:1.55;color:#374151">%s</p>
                </div>
                %s
              </div>
            </body>
            </html>
            """.formatted(
                title,                      // <title> left
                branding.brandName(),       // <title> right
                logoUrl,                    // header logo src
                branding.brandName(),       // header logo alt
                branding.brandName(),       // header brand text
                safeName,                   // Hello, X
                lead,                       // "Password created/changed ..."
                branding.brandName(),       // "... at BRAND"
                sub,                        // explanation / security note
                actionHref,                 // CTA href
                actionLabel,                // CTA label
                advisory,                   // extra advisory
                EmailFooter.generate()      // footer
        );
    }

    private static String escapeHtml(String s) {
        return s.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
                .replace("\"","&quot;").replace("'","&#x27;");
    }
}
