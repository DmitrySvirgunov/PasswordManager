package ru.dmitrysvirgunov.passwordmanager.vault.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import ru.dmitrysvirgunov.passwordmanager.vault.entity.VaultSharingAttempt;
import ru.dmitrysvirgunov.passwordmanager.vault.model.VaultSharingAttemptAction;

import java.time.OffsetDateTime;
import java.util.UUID;

public interface VaultSharingAttemptRepository extends JpaRepository<VaultSharingAttempt, UUID> {

    long countByActionAndActorUserIdAndCreatedAtAfter(
            VaultSharingAttemptAction action,
            UUID actorUserId,
            OffsetDateTime createdAtAfter
    );

    long countByActionAndVaultIdAndCreatedAtAfter(
            VaultSharingAttemptAction action,
            UUID vaultId,
            OffsetDateTime createdAtAfter
    );

    long countByActionAndActorUserIdAndTargetEmailHashAndCreatedAtAfter(
            VaultSharingAttemptAction action,
            UUID actorUserId,
            byte[] targetEmailHash,
            OffsetDateTime createdAtAfter
    );
}
