package ru.dmitrysvirgunov.passwordmanager.auth.listener;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.mail.MailException;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;
import ru.dmitrysvirgunov.passwordmanager.auth.event.RegistrationVerificationEmailRequestedEvent;
import ru.dmitrysvirgunov.passwordmanager.auth.service.RegistrationEmailService;

@Slf4j
@Component
@RequiredArgsConstructor
public class RegistrationEmailListener {

    private final RegistrationEmailService registrationEmailService;

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void handle(RegistrationVerificationEmailRequestedEvent event) {
        try {
            registrationEmailService.sendVerificationEmail(
                    event.email(),
                    event.rawToken()
            );
        } catch (MailException ex) {
            log.error("Failed to send verification email to {}", event.email(), ex);
        }
    }
}
