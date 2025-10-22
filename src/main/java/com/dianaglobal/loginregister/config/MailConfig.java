// src/main/java/com/dianaglobal/loginregister/config/MailConfig.java
package com.dianaglobal.loginregister.config;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.Properties;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.mail.javamail.MimeMessagePreparator;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;

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
        
        // Configurações para prevenir truncamento de emails
        props.put("mail.smtp.connectiontimeout", "60000");
        props.put("mail.smtp.timeout", "60000");
        props.put("mail.smtp.writetimeout", "60000");
        props.put("mail.mime.charset", "UTF-8");
        props.put("mail.mime.address.strict", "false");
        
        // Se usar 465/SSL: props.put("mail.smtp.ssl.enable", "true");
        return impl;
    }

    @Bean
    public MailBranding mailBranding(
            @Value("${application.brand.name:Diana Global}") String brandName,
            @Value("${brand.frontend-url:https://www.dianaglobal.com.br}") String frontendUrl,
            @Value("${application.brand.logo-url:https://www.andescoresoftware.com.br/AndesCore.jpg}") String logoUrl
    ) {
        return new MailBranding(brandName, frontendUrl, logoUrl);
    }

    public record MailBranding(String brandName, String frontendUrl, String logoUrl) {
        public String safeLogoUrl() {
            // fallback mínimo se vier vazio
            return (logoUrl == null || logoUrl.isBlank())
                    ? "https://www.andescoresoftware.com.br/AndesCore.jpg"
                    : logoUrl;
        }
    }

    /**
     * Creates a properly configured MimeMessageHelper to prevent email truncation
     * 
     * @param message the MimeMessage to configure
     * @param fromAddress the sender email address
     * @param brandName the sender name
     * @return configured MimeMessageHelper
     */
    public static MimeMessageHelper createHelper(MimeMessage message, String fromAddress, String brandName) {
        try {
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
            
            // Set additional headers to prevent truncation
            message.setHeader("X-Priority", "3");
            message.setHeader("X-MSMail-Priority", "Normal");
            message.setHeader("Importance", "Normal");
            message.setHeader("X-Mailer", "DianaGlobal Email System");
            
            // Set sender with proper encoding
            try {
                helper.setFrom(fromAddress, brandName);
            } catch (MessagingException | UnsupportedEncodingException e) {
                helper.setFrom(fromAddress);
            }
            
            return helper;
        } catch (MessagingException e) {
            throw new RuntimeException("Failed to create MimeMessageHelper", e);
        }
    }

    /**
     * Creates a MimeMessagePreparator with proper configuration
     * 
     * @param toEmail recipient email
     * @param subject email subject
     * @param htmlContent email HTML content
     * @param fromAddress sender email
     * @param brandName sender name
     * @return configured MimeMessagePreparator
     */
    public static MimeMessagePreparator createPreparator(String toEmail, String subject, String htmlContent, 
                                                         String fromAddress, String brandName) {
        return mimeMessage -> {
            MimeMessageHelper helper = createHelper(mimeMessage, fromAddress, brandName);
            helper.setTo(toEmail);
            helper.setSubject(subject);
            helper.setText(htmlContent, true);
        };
    }
}
