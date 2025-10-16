package com.dianaglobal.loginregister.adapter.out.mail;

import com.dianaglobal.loginregister.config.MailConfig.MailBranding;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.time.Year;

@Slf4j
@Component
@RequiredArgsConstructor
public class EmailChangeEmailService {

    private final JavaMailSender mailSender;
    private final MailBranding branding;

    @Value("${mail.username}")
    private String fromAddress;

    /** [a] Ask confirmation in the NEW e-mail. */
    public void sendConfirmNew(String toEmail, String name, String confirmLink, int minutes) {
        String subject = "Confirm your new e-mail";
        String html = buildHtmlConfirm(name, confirmLink, minutes);
        sendHtml(toEmail, subject, html);
    }

    /** [c] Notify the NEW e-mail after change. */
    public void sendChanged(String toEmail, String name) {
        String subject = "Your account e-mail was updated";
        String html = buildHtmlChanged(name);
        sendHtml(toEmail, subject, html);
    }

    /** [b] Optional alert to OLD e-mail. */
    public void sendAlertOld(String oldEmail, String name, String supportUrl) {
        String subject = "Security alert: request to change your e-mail";
        String html = buildHtmlAlertOld(name, supportUrl);
        sendHtml(oldEmail, subject, html);
    }

    /* ========== send helper ========== */
    private void sendHtml(String toEmail, String subject, String html) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, false, StandardCharsets.UTF_8.name());
            helper.setTo(toEmail);
            helper.setSubject(subject);
            helper.setText(html, true);
            try {
                helper.setFrom(fromAddress, branding.brandName());
            } catch (Exception ignore) {
                helper.setFrom(fromAddress);
            }
            mailSender.send(message);
            log.info("[MAIL] Sent '{}' to {}", subject, toEmail);
        } catch (Exception e) {
            log.error("[MAIL] Error sending '{}' to {}: {}", subject, toEmail, e.getMessage(), e);
        }
    }

    /* ========== html helpers (padronizados) ========== */
    private static String imgBoiler(String url, String alt, int w, int h) {
        return """
          <img src="%s" alt="%s" width="%d" height="%d"
               style="display:block;border:0;outline:none;text-decoration:none;-ms-interpolation-mode:bicubic;border-radius:6px">
        """.formatted(url, alt, w, h);
    }

    private String header(String subtitle) {
        String logoUrl = branding.safeLogoUrl();
        return """
          <tr>
            <td style="background:linear-gradient(135deg,#0a2239,#0e4b68);padding:16px 20px;color:#fff;border-top-left-radius:12px;border-top-right-radius:12px">
              <table role="presentation" width="100%%" cellspacing="0" cellpadding="0">
                <tr>
                  <td width="64" valign="middle">%s</td>
                  <td align="right" valign="middle" style="font-family:Arial,Helvetica,sans-serif">
                    <div style="font-weight:700;font-size:18px;line-height:1"><strong>%s</strong></div>
                    <div style="height:6px;line-height:6px;font-size:0">&nbsp;</div>
                    <div style="opacity:.9;font-size:12px;line-height:1.2">%s</div>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
        """.formatted(imgBoiler(logoUrl, branding.brandName(), 56, 56), branding.brandName(), subtitle);
    }

    private String footer() {
        int year = Year.now().getValue();
        return """
          <tr>
            <td style="background:linear-gradient(135deg,#0a2239,#0e4b68);padding:8px 18px;text-align:center;color:#fff;border-bottom-left-radius:12px;border-bottom-right-radius:12px">
              <span role="img" aria-label="lightning" style="color:#ffd200;font-size:22px;vertical-align:middle">&#9889;&#xfe0e;</span>
              <span style="vertical-align:middle;font-family:Arial,Helvetica,sans-serif;font-size:14px;line-height:1">
                &#8203;© %d · Powered by <strong>AndesCore Software</strong>
              </span>
            </td>
          </tr>
        """.formatted(year);
    }

    private String shell(String title, String bodyRows) {
        return """
          <!doctype html>
          <html lang="en">
          <head>
            <meta charset="utf-8"><meta name="viewport" content="width=device-width">
            <title>%s</title><style>img{display:block}</style>
          </head>
          <body style="margin:0;padding:24px;background:#f6f7f9">
            <table role="presentation" width="100%%" cellspacing="0" cellpadding="0" align="center">
              <tr><td align="center">
                <table role="presentation" width="640" cellspacing="0" cellpadding="0" style="max-width:640px;background:#fff;border:1px solid #eee;border-radius:12px">
                  %s
                  %s
                  %s
                </table>
              </td></tr>
            </table>
          </body></html>
        """.formatted(title, header(title), bodyRows, footer());
    }

    /* ========== templates específicos ========== */
    private String buildHtmlConfirm(String name, String confirmLink, int minutes) {
        String safe = (name == null || name.isBlank()) ? "there" : escapeHtml(name);
        String body = """
          <tr><td style="padding:24px;font-family:Arial,Helvetica,sans-serif;color:#111827">
            <p style="font-size:16px;margin:0 0 12px">Hello, <strong>%s</strong>!</p>
            <p style="margin:0 0 12px;line-height:1.55">
              We received a request to update the e-mail on your account. Click the button below to confirm.
              This link expires in <strong>%d minutes</strong>.
            </p>
            <p style="margin:20px 0">
              <a href="%s" target="_blank" rel="noopener noreferrer"
                 style="display:inline-block;padding:12px 18px;border-radius:6px;text-decoration:none;background:#111827;color:#fff;font-weight:600">
                Confirm new e-mail
              </a>
            </p>
          </td></tr>
        """.formatted(safe, minutes, confirmLink);
        return shell("Confirm new e-mail", body);
    }

    private String buildHtmlChanged(String name) {
        String safe = (name == null || name.isBlank()) ? "there" : escapeHtml(name);
        String loginUrl = branding.frontendUrl() + "/login";
        String body = """
          <tr><td style="padding:24px;font-family:Arial,Helvetica,sans-serif;color:#111827">
            <p style="font-size:16px;margin:0 0 12px">Hello, <strong>%s</strong>!</p>
            <p style="margin:0 0 12px;line-height:1.55">
              The e-mail on your account has been updated successfully. You can now log in using the new e-mail.
            </p>
            <p style="margin:20px 0">
              <a href="%s" target="_blank" rel="noopener noreferrer"
                 style="display:inline-block;padding:12px 18px;border-radius:6px;text-decoration:none;background:#111827;color:#fff;font-weight:600">
                Go to login
              </a>
            </p>
          </td></tr>
        """.formatted(safe, loginUrl);
        return shell("E-mail updated", body);
    }

    private String buildHtmlAlertOld(String name, String supportUrl) {
        String safe = (name == null || name.isBlank()) ? "there" : escapeHtml(name);
        String url = (supportUrl == null || supportUrl.isBlank()) ? (branding.frontendUrl() + "/support") : supportUrl;
        String body = """
          <tr><td style="padding:24px;font-family:Arial,Helvetica,sans-serif;color:#111827">
            <p style="font-size:16px;margin:0 0 12px">Hello, <strong>%s</strong>!</p>
            <p style="margin:0 0 12px;line-height:1.55">
              We received a request to change the e-mail on your account. If this wasn't you, please contact support immediately:
            </p>
            <p style="margin:20px 0">
              <a href="%s" target="_blank" rel="noopener noreferrer"
                 style="display:inline-block;padding:12px 18px;border-radius:6px;text-decoration:none;background:#b91c1c;color:#fff;font-weight:600">
                Contact support
              </a>
            </p>
          </td></tr>
        """.formatted(safe, url);
        return shell("Security alert", body);
    }

    private static String escapeHtml(String s) {
        return s == null ? "" : s.replace("&", "&amp;")
                .replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&#x27;");
    }
}
