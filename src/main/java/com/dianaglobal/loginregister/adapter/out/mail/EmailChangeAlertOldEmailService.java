// src/main/java/com/dianaglobal/loginregister/adapter/out/mail/EmailChangeAlertOldEmailService.java
package com.dianaglobal.loginregister.adapter.out.mail;

import java.nio.charset.StandardCharsets;
import java.time.Year;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Component;

import com.dianaglobal.loginregister.config.MailConfig.MailBranding;

import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
@RequiredArgsConstructor
public class EmailChangeAlertOldEmailService {

    private final JavaMailSender mailSender;
    private final MailBranding branding;

    @Value("${mail.username}") private String fromAddress;

    /** Alerta para o e-mail ANTIGO. */
    public void sendAlertOld(String oldEmail, String name, String supportUrl) {
        final String subject = "Security alert: e-mail change detected";
        final String html = buildHtml(name, supportUrl, subject);
        sendHtml(oldEmail, subject, html);
    }

    private void sendHtml(String toEmail, String subject, String html) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, StandardCharsets.UTF_8.name());
            helper.setTo(toEmail);
            helper.setSubject(subject);
            helper.setText(html, true);
            try { helper.setFrom(fromAddress, branding.brandName()); } catch (Exception ignore) { helper.setFrom(fromAddress); }
            mailSender.send(message);
            log.info("[MAIL] Sent '{}' to {}", subject, toEmail);
        } catch (Exception e) {
            log.error("[MAIL] Error sending '{}' to {}: {}", subject, toEmail, e.getMessage(), e);
        }
    }

    private String buildHtml(String name, String supportUrl, String pageTitle) {
        final String brand = branding.brandName();
        final String safeName = (name == null || name.isBlank()) ? "there" : escapeHtml(name);
        final String safeLogo = normalizeLogoUrl(branding.safeLogoUrl()); // <- força https/absoluto
        final String url = (supportUrl == null || supportUrl.isBlank())
                ? (branding.frontendUrl() + "/support")
                : supportUrl;
        final int year = Year.now().getValue();

        return """
            <!doctype html>
            <html lang="en">
            <head>
              <meta charset="utf-8">
              <meta name="viewport" content="width=device-width, initial-scale=1">
              <title>%s · %s</title>
              <style>img{display:block}</style>
            </head>
            <body style="margin:0;padding:24px;background:#f6f7f9;font-family:Arial,Helvetica,sans-serif;color:#111827;">
              <table role="presentation" width="100%%" cellspacing="0" cellpadding="0" border="0">
                <tr>
                  <td align="center">
                    <table role="presentation" width="640" cellspacing="0" cellpadding="0" border="0" style="max-width:640px;background:#ffffff;border:1px solid #e5e7eb;border-radius:12px;overflow:hidden;">
                      %s
                      <tr>
                        <td style="padding:24px;">
                          <p style="font-size:16px;line-height:1.5;margin:0 0 12px;">Hello, <strong>%s</strong>!</p>
                          <p style="font-size:14px;line-height:1.6;margin:0 0 16px;">
                            We received a request to change the e-mail on your account. If this wasn't you, please contact support immediately.
                          </p>
                          %s
                        </td>
                      </tr>
                      %s
                    </table>
                  </td>
                </tr>
              </table>
            </body>
            </html>
            """.formatted(
                pageTitle, brand,
                header("Security alert", safeLogo, brand),
                safeName,
                ctaButton(url, "Contact support"),
                footer(year)
        );
    }

    private String header(String subtitle, String logoUrl, String brand) {
        return """
            <tr>
              <td style="padding:0;background:linear-gradient(135deg,#0a2239,#0e4b68);">
                <table role="presentation" width="100%%" cellspacing="0" cellpadding="0" border="0" style="color:#ffffff;">
                  <tr>
                    <td style="padding:16px 20px;">
                      <table role="presentation" width="100%%" cellspacing="0" cellpadding="0" border="0">
                        <tr>
                          <td width="72" valign="middle" style="padding:0;margin:0;">
                            %s
                          </td>
                          <td align="right" valign="middle" style="padding:0;margin:0;">
                            <div style="font-weight:700;font-size:18px;line-height:1;">%s</div>
                            <div style="height:6px;line-height:6px;font-size:0;">&nbsp;</div>
                            <div style="opacity:.9;font-size:12px;line-height:1.2;margin-top:4px;">%s</div>
                          </td>
                        </tr>
                      </table>
                    </td>
                  </tr>
                </table>
              </td>
            </tr>
            """.formatted(
                imgBoiler(logoUrl, brand, 64, 64, true), // 64x64 para maior presença visual
                escapeHtml(brand),
                escapeHtml(subtitle)
        );
    }

    /** Footer centralizado com mini-tabela para evitar desalinhamento do emoji em Gmail/Outlook/iOS. */
    private String footer(int year) {
        return """
            <tr>
              <td style="padding:6px 18px;background:linear-gradient(135deg,#0a2239,#0e4b68);text-align:center;color:#ffffff;font-size:14px;line-height:1;">
                <span role="img" aria-label="raio" style="color:#ffd200;font-size:22px;vertical-align:middle;">&#x26A1;&#xFE0E;</span>
                <span style="vertical-align:middle;">© %d · Powered by <strong>AndesCore Software</strong></span>
              </td>
            </tr>
            """.formatted(year);
    }

    private String ctaButton(String href, String label) {
        return """
            <table role="presentation" cellspacing="0" cellpadding="0" border="0" style="margin:20px 0;">
              <tr>
                <td align="left">
                  <a href="%s" target="_blank" rel="noopener noreferrer"
                     style="display:inline-block;background:#111827;color:#ffffff;text-decoration:none;font-weight:600;
                            padding:12px 18px;border-radius:8px;font-size:14px;">
                    %s
                  </a>
                </td>
              </tr>
            </table>
            """.formatted(escapeHtml(href), escapeHtml(label));
    }

    private String imgBoiler(String url, String alt, int width, int height, boolean rounded) {
        final String src = escapeHtml(url);
        final String radius = rounded ? "6px" : "0";
        return """
            <img src="%s" alt="%s" width="%d" height="%d"
                 style="display:block;outline:none;border:none;text-decoration:none;-ms-interpolation-mode:bicubic;
                        width:%dpx;height:%dpx;border-radius:%s;">
            """.formatted(
                src, escapeHtml(alt),
                width, height, width, height, radius
        );
    }

    /** Garante URL absoluta e HTTPS para reduzir bloqueio por clientes. */
    private static String normalizeLogoUrl(String url) {
        if (url == null) return "";
        String u = url.trim();
        if (u.isEmpty()) return "";
        if (u.startsWith("//")) return "https:" + u;
        if (u.startsWith("http://")) return "https://" + u.substring(7);
        return u; // já https ou data: etc.
    }

    private static String escapeHtml(String s) {
        return s == null ? "" : s.replace("&","&amp;")
                .replace("<","&lt;").replace(">","&gt;")
                .replace("\"","&quot;").replace("'","&#x27;");
    }
}
