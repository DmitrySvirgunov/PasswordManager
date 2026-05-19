package ru.dmitrysvirgunov.passwordmanager.vault.repository;

import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import ru.dmitrysvirgunov.passwordmanager.vault.entity.Vault;

import java.util.Optional;
import java.util.UUID;

public interface VaultRepository extends JpaRepository<Vault, UUID> {

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("""
            select v
            from Vault v
            where v.vaultId = :vaultId
            """)
    Optional<Vault> findByVaultIdForUpdate(UUID vaultId);
}