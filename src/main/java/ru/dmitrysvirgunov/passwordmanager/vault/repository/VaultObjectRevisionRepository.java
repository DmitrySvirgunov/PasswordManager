package ru.dmitrysvirgunov.passwordmanager.vault.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import ru.dmitrysvirgunov.passwordmanager.vault.entity.VaultObjectRevision;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface VaultObjectRevisionRepository extends JpaRepository<VaultObjectRevision, UUID> {

    Optional<VaultObjectRevision> findByObjectIdAndVersion(UUID objectId, int version);

    List<VaultObjectRevision> findByObjectIdOrderByVersionDesc(UUID objectId);
}