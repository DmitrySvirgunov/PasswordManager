package ru.dmitrysvirgunov.passwordmanager.auth.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import ru.dmitrysvirgunov.passwordmanager.auth.entity.AuthAttempt;
import ru.dmitrysvirgunov.passwordmanager.auth.repository.AuthAttemptRepository;

@Service
@RequiredArgsConstructor
public class AuthAttemptService {

    private final AuthAttemptRepository authAttemptRepository;

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void save(AuthAttempt authAttempt) {
        authAttemptRepository.save(authAttempt);
    }
}