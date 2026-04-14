package ru.dmitrysvirgunov.passwordmanager.auth.service;

import lombok.RequiredArgsConstructor;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;
import ru.dmitrysvirgunov.passwordmanager.config.MailProperties;

@RequiredArgsConstructor
public class SmtpRegistrationEmailService implements RegistrationEmailService {

    private final JavaMailSender mailSender;
    private final MailProperties mailProperties;

    @Override
    public void sendVerificationEmail(String email, String rawToken) {
        String verifyLink = mailProperties.verifyBaseUrl() + "?token=" + rawToken;

        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(mailProperties.from());
        message.setTo(email);
        message.setSubject("Подтверждение почты");
        message.setText("""
                Завершите регистрацию.

                Для подтверждения почты перейдите по ссылке:
                %s

                Если это были не вы, просто проигнорируйте письмо.
                """.formatted(verifyLink));

        mailSender.send(message);
    }
}