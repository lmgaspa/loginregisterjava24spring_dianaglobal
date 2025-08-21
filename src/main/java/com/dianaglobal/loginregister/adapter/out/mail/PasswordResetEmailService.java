package com.dianaglobal.loginregister.adapter.out.mail;

import jakarta.annotation.PostConstruct;
import jakarta.mail.internet.MimeMessage;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.mail.javamail.MimeMessageHelper;

import java.nio.charset.StandardCharsets;
import java.util.Properties;

@Slf4j
@Service
public class PasswordResetEmailService {

    // ====== Lendo dos envs conforme seu application.yml ======
    @Value("${mail.host}") private String host;
    @Value("${mail.port}") private int port;
    @Value("${mail.username}") private String username;
    @Value("${mail.password}") private String password;
    @Value("${mail.properties.mail.smtp.auth:true}") private boolean smtpAuth;
    @Value("${mail.properties.mail.smtp.starttls.enable:true}") private boolean startTls;

    // Nome/brand – usa application.name se existir; fallback para "Diana Global"
    @Value("${application.name:Diana Global}") private String brandName;

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
        // Opcional: debug
        // props.put("mail.debug", "true");

        this.mailSender = impl;
        log.info("PasswordResetEmailService initialized with host={} port={}", host, port);
    }

    /**
     * Envia o e‑mail de recuperação com o link e expiração.
     * @param to e‑mail do usuário
     * @param name nome do usuário (pode ser null)
     * @param link URL completa para redefinição (https://.../reset-password?token=...)
     * @param minutes validade do link em minutos (ex.: 45)
     */
    public void sendPasswordReset(String to, String name, String link, int minutes) {
        try {
            String subject = brandName + " – Recuperação de Senha";
            String html = buildHtml(name, link, minutes);

            MimeMessage message = ((JavaMailSenderImpl) mailSender).createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, MimeMessageHelper.MULTIPART_MODE_MIXED_RELATED, StandardCharsets.UTF_8.name());
            helper.setTo(to);
            helper.setSubject(subject);
            helper.setText(html, true);
            // Remetente opcional: se seu provedor exigir um "from" específico:
            // helper.setFrom(username, brandName);

            mailSender.send(message);
        } catch (Exception e) {
            log.error("Erro ao enviar e‑mail de recuperação para {}: {}", to, e.getMessage(), e);
            throw new RuntimeException("Falha ao enviar e‑mail de recuperação", e);
        }
    }

    // ====== HTML embutido (estilo limpo, similar ao do seu recibo) ======
    private String buildHtml(String name, String link, int minutes) {
        String safeName = (name == null || name.isBlank()) ? "cliente" : name;
        return """
            <!doctype html>
            <html lang="pt-BR">
            <head>
              <meta charset="utf-8">
              <meta name="viewport" content="width=device-width"/>
              <title>%s – Recuperação de Senha</title>
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
                <div class="header">%s – Recuperação de Senha</div>
                <div class="content">
                  <p class="greet">Olá, %s!</p>
                  <p class="p">Recebemos uma solicitação para redefinir a sua senha.</p>
                  <p class="p">Para continuar, clique no botão abaixo. O link expira em <strong>%d minutos</strong>.</p>
                  <p style="margin:20px 0">
                    <a class="btn" href="%s" target="_blank" rel="noopener noreferrer">Redefinir minha senha</a>
                  </p>
                  <p class="p">Se você não solicitou essa alteração, ignore este e‑mail com segurança.</p>
                  <p class="muted">Se o botão não funcionar, copie e cole este link no navegador:<br>%s</p>
                </div>
                <div class="footer">
                  © 2025 %s. Todos os direitos reservados.
                </div>
              </div>
            </body>
            </html>
            """.formatted(brandName, brandName, escapeHtml(safeName), minutes, link, link, brandName);
    }

    // Bem simples; suficiente para nome. O link não passa por aqui.
    private static String escapeHtml(String s) {
        return s.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
                .replace("\"","&quot;").replace("'","&#x27;");
    }
}
