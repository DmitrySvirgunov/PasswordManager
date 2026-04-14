package ru.dmitrysvirgunov.passwordmanager.config;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mail.javamail.JavaMailSender;
import ru.dmitrysvirgunov.passwordmanager.auth.service.LoggingRegistrationEmailService;
import ru.dmitrysvirgunov.passwordmanager.auth.service.NoopRegistrationEmailService;
import ru.dmitrysvirgunov.passwordmanager.auth.service.RegistrationEmailService;
import ru.dmitrysvirgunov.passwordmanager.auth.service.SmtpRegistrationEmailService;

@Configuration
public class MailConfig {

    @Bean
    public RegistrationEmailService registrationEmailService(
            MailModeProperties mailModeProperties,
            MailProperties mailProperties,
            ObjectProvider<JavaMailSender> javaMailSenderProvider
    ) {
        return switch (mailModeProperties.mode()) {
            case SMTP -> {
                JavaMailSender javaMailSender = javaMailSenderProvider.getIfAvailable();
                if (javaMailSender == null) {
                    throw new IllegalStateException(
                            "JavaMailSender bean is required for mail mode: " + mailModeProperties.mode()
                    );
                }
                yield new SmtpRegistrationEmailService(javaMailSender, mailProperties);
            }
            case LOG -> new LoggingRegistrationEmailService(mailProperties);
            case NOOP -> new NoopRegistrationEmailService();
        };
    }
}