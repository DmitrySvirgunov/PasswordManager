package ru.dmitrysvirgunov.passwordmanager.vault.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import ru.dmitrysvirgunov.passwordmanager.vault.entity.VaultSharingAttempt;
import ru.dmitrysvirgunov.passwordmanager.vault.repository.VaultSharingAttemptRepository;

@Service
@RequiredArgsConstructor
public class VaultSharingAttemptService {

    private final VaultSharingAttemptRepository vaultSharingAttemptRepository;

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void save(VaultSharingAttempt attempt) {
        vaultSharingAttemptRepository.save(attempt);
    }
}
