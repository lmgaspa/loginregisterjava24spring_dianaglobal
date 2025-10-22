// src/main/java/com/dianaglobal/loginregister/adapter/out/mail/WelcomeEmailService.java
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
public class WelcomeEmailService {

    private final JavaMailSender mailSender;
    private final MailBranding branding;

    @Value("${mail.username}") private String fromAddress; // só o remetente

    public void send(String toEmail, String name) {
        try {
            String subject = "🎉 Welcome to " + branding.brandName() + "!";
            String html = buildHtml(name);

            MimeMessagePreparator preparator = MailConfig.createPreparator(toEmail, subject, html, fromAddress, branding.brandName());
            mailSender.send(preparator);
            
            log.info("Welcome e-mail sent to {}", toEmail);
        } catch (MailSendException e) {
            log.error("Error sending welcome e-mail to {}: {}", toEmail, e.getMessage(), e);
        }
    }

    private String buildHtml(String name) {
        String safeName = (name == null || name.isBlank()) ? "there" : escapeHtml(name);
        String logoUrl = branding.safeLogoUrl();

        return """
            <!doctype html>
            <html lang="en">
            <head>
              <meta charset="utf-8">
              <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
              <title>Welcome to %s</title>
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
                        <div style="opacity:.9;font-size:12px;line-height:1.2;margin-top:4px;">Welcome to our platform</div>
                      </td>
                    </tr>
                  </table>
                </div>

                <div style="padding:24px">
                  <p style="font-size:16px;margin:0 0 12px">Hello, <strong>%s</strong>!</p>
                  <p style="margin:0 0 12px;line-height:1.55">
                    We're thrilled to have you on board. Your account has been successfully created at <strong>%s</strong>.
                  </p>
                  <p style="margin:20px 0">
                    <a href="%s/login" target="_blank" rel="noopener noreferrer"
                       style="display:inline-block;padding:12px 18px;border-radius:6px;text-decoration:none;
                              background:#111827;color:#fff;font-weight:600">
                      Access your account
                    </a>
                  </p>
                </div>

                %s
              </div>
            </body>
            </html>
            """.formatted(
                branding.brandName(),
                logoUrl,
                branding.brandName(),
                branding.brandName(),
                safeName,
                branding.brandName(),
                branding.frontendUrl(),
                EmailFooter.generate()
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
