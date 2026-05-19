package ru.dmitrysvirgunov.passwordmanager.auth.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import ru.dmitrysvirgunov.passwordmanager.auth.entity.UserKeyMaterialHistory;

import java.util.Optional;
import java.util.UUID;

public interface UserKeyMaterialHistoryRepository extends JpaRepository<UserKeyMaterialHistory, UUID> {
    Optional<UserKeyMaterialHistory> findTopByUserIdAndSigningKeyVersionOrderByArchivedAtDesc(
            UUID userId,
            int signingKeyVersion
    );
}
