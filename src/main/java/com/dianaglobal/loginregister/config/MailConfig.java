// src/main/java/com/dianaglobal/loginregister/config/MailConfig.java
package com.dianaglobal.loginregister.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mail.javamail.JavaMailSenderImpl;

import java.nio.charset.StandardCharsets;
import java.util.Properties;

@Configuration
public class MailConfig {

    @Value("${mail.host}") private String host;
    @Value("${mail.port}") private int port;
    @Value("${mail.username}") private String username;
    @Value("${mail.password}") private String password;
    @Value("${mail.properties.mail.smtp.auth:true}") private boolean smtpAuth;
    @Value("${mail.properties.mail.smtp.starttls.enable:true}") private boolean startTls;

    @Bean
    public org.springframework.mail.javamail.JavaMailSender mailSender() {
        JavaMailSenderImpl impl = new JavaMailSenderImpl();
        impl.setHost(host);
        impl.setPort(port);
        impl.setUsername(username);
        impl.setPassword(password);
        impl.setDefaultEncoding(StandardCharsets.UTF_8.name());

        Properties props = impl.getJavaMailProperties();
        props.put("mail.smtp.auth", Boolean.toString(smtpAuth));
        props.put("mail.smtp.starttls.enable", Boolean.toString(startTls));
        // Se usar 465/SSL: props.put("mail.smtp.ssl.enable", "true");
        return impl;
    }

    @Bean
    public MailBranding mailBranding(
            @Value("${application.brand.name:Diana Global}") String brandName,
            @Value("${application.brand.frontend-url:https://www.dianaglobal.com.br}") String frontendUrl,
            @Value("${application.brand.logo-url:https://www.andescoresoftware.com.br//AndesCore.jpg}") String logoUrl
    ) {
        return new MailBranding(brandName, frontendUrl, logoUrl);
    }

    public record MailBranding(String brandName, String frontendUrl, String logoUrl) {
        public String safeLogoUrl() {
            // fallback mínimo se vier vazio
            return (logoUrl == null || logoUrl.isBlank())
                    ? "https://www.dianaglobal.com.br/logo.png"
                    : logoUrl;
        }
    }
}
