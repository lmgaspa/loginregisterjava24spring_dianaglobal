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
import java.util.UUID;

@Slf4j
@Component
@RequiredArgsConstructor
public class AccountConfirmationEmailService {

    private final JavaMailSender mailSender;
    private final MailBranding branding;

    @Value("${mail.username}")
    private String fromAddress;

    /** Assinatura esperada pelo AccountConfirmationService */
    public void send(String toEmail, String name, String confirmLink, int minutes) {
        final String subject = "Confirm your e-mail";
        final String html = buildHtml(name, confirmLink, minutes);
        sendHtml(toEmail, subject, html);
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

    /* ========== html builders ========== */
    private static String imgBoiler(String url, String alt, int w, int h) {
        return """
          <img src="%s" alt="%s" width="%d" height="%d"
               style="display:block;border:0;outline:none;text-decoration:none;-ms-interpolation-mode:bicubic;border-radius:6px">
        """.formatted(url, alt, w, h);
    }

    private String buildHtml(String name, String confirmLink, int minutes) {
        final String safeName = (name == null || name.isBlank()) ? "there" : escapeHtml(name);
        final int year = Year.now().getValue();
        final String msgId = UUID.randomUUID().toString();
        final String logoUrl = branding.safeLogoUrl();
        final String preheader = "Confirm your e-mail address to finish creating your account.";

        String header = """
          <tr>
            <td style="background:linear-gradient(135deg,#0a2239,#0e4b68);padding:16px 20px;color:#fff;border-top-left-radius:12px;border-top-right-radius:12px">
              <table role="presentation" width="100%%" cellspacing="0" cellpadding="0">
                <tr>
                  <td width="64" valign="middle">%s</td>
                  <td align="right" valign="middle" style="font-family:Arial,Helvetica,sans-serif">
                    <div style="font-weight:700;font-size:18px;line-height:1"><strong>%s</strong></div>
                    <div style="height:6px;line-height:6px;font-size:0">&nbsp;</div>
                    <div style="opacity:.9;font-size:12px;line-height:1.2">Confirm your e-mail</div>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
        """.formatted(imgBoiler(logoUrl, branding.brandName(), 56, 56), branding.brandName());

        String body = """
          <tr>
            <td style="padding:24px;font-family:Arial,Helvetica,sans-serif;color:#111827">
              <p style="font-size:16px;margin:0 0 12px">Hello, <strong>%s</strong>!</p>
              <p style="margin:0 0 12px;line-height:1.55">
                Thanks for signing up. To finish creating your account, please confirm your e-mail address.
                This link expires in <strong>%d minutes</strong>.
              </p>
              <p style="margin:20px 0">
                <a href="%s" target="_blank" rel="noopener noreferrer"
                   style="display:inline-block;padding:12px 18px;border-radius:6px;text-decoration:none;background:#111827;color:#fff;font-weight:600">
                  Confirm e-mail
                </a>
              </p>
              <p style="margin:0 0 12px;line-height:1.55;color:#374151">
                If you didn’t request this, please ignore this message or contact support.
              </p>
            </td>
          </tr>
        """.formatted(safeName, minutes, confirmLink);

        // zero-width space (&#8203;) no rodapé para evitar “assinatura” repetida do Gmail
        String footer = """
          <tr>
            <td style="background:linear-gradient(135deg,#0a2239,#0e4b68);padding:8px 18px;text-align:center;color:#fff;border-bottom-left-radius:12px;border-bottom-right-radius:12px">
              <span role="img" aria-label="lightning" style="color:#ffd200;font-size:22px;vertical-align:middle">&#9889;&#xfe0e;</span>
              <span style="vertical-align:middle;font-family:Arial,Helvetica,sans-serif;font-size:14px;line-height:1">
                &#8203;© %d · Powered by <strong>AndesCore Software</strong> · id:%s
              </span>
            </td>
          </tr>
        """.formatted(year, msgId);

        return """
          <!doctype html>
          <html lang="en">
          <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width">
            <title>Confirm your e-mail · %s</title>
            <style>img{display:block}</style>
          </head>
          <body style="margin:0;padding:24px;background:#f6f7f9">
            <!-- preheader (hidden) -->
            <div style="display:none;max-height:0;overflow:hidden;opacity:0;color:transparent;">%s</div>

            <table role="presentation" width="100%%" cellspacing="0" cellpadding="0" align="center">
              <tr>
                <td align="center">
                  <table role="presentation" width="640" cellspacing="0" cellpadding="0" style="max-width:640px;background:#ffffff;border:1px solid #eee;border-radius:12px">
                    %s
                    %s
                    %s
                  </table>
                </td>
              </tr>
            </table>
          </body>
          </html>
        """.formatted(branding.brandName(), preheader, header, body, footer);
    }

    private static String escapeHtml(String s) {
        return s == null ? "" : s.replace("&", "&amp;")
                .replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&#x27;");
    }
}
