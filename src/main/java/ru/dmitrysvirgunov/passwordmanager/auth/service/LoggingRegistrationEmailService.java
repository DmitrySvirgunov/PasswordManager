package ru.dmitrysvirgunov.passwordmanager.auth.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import ru.dmitrysvirgunov.passwordmanager.config.MailProperties;

@Slf4j
@RequiredArgsConstructor
public class LoggingRegistrationEmailService implements RegistrationEmailService {

    private final MailProperties mailProperties;

    @Override
    public void sendVerificationEmail(String email, String rawToken) {
        String verifyLink = mailProperties.verifyBaseUrl() + "?token=" + rawToken;

        log.info("""
                [DEV EMAIL]
                to={}
                subject=Подтверждение почты
                link={}
                """, email, verifyLink);
    }
}