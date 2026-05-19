package ru.dmitrysvirgunov.passwordmanager.vault.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import ru.dmitrysvirgunov.passwordmanager.vault.entity.VaultKeyEnvelope;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface VaultKeyEnvelopeRepository extends JpaRepository<VaultKeyEnvelope, UUID> {

    @Query("""
            select e
            from VaultKeyEnvelope e
            where e.vaultId = :vaultId
              and e.recipientUserId = :recipientUserId
              and e.vaultKeyVersion = :vaultKeyVersion
              and e.recipientEncryptionKeyVersion = :recipientEncryptionKeyVersion
              and e.revokedAt is null
            """)
    Optional<VaultKeyEnvelope> findActiveEnvelope(
            UUID vaultId,
            UUID recipientUserId,
            int vaultKeyVersion,
            int recipientEncryptionKeyVersion
    );

    @Query("""
            select e
            from VaultKeyEnvelope e
            where e.vaultId = :vaultId
              and e.recipientUserId = :recipientUserId
              and e.revokedAt is null
            order by e.vaultKeyVersion desc, e.recipientEncryptionKeyVersion desc
            """)
    List<VaultKeyEnvelope> findActiveEnvelopesForRecipient(
            UUID vaultId,
            UUID recipientUserId
    );

    @Query("""
            select e
            from VaultKeyEnvelope e
            where e.vaultId = :vaultId
              and e.recipientUserId = :recipientUserId
              and e.revokedAt is null
            """)
    List<VaultKeyEnvelope> findActiveEnvelopes(
            UUID vaultId,
            UUID recipientUserId
    );

    @Query("""
        select e
        from VaultKeyEnvelope e
        join Vault v on v.vaultId = e.vaultId
        where e.recipientUserId = :recipientUserId
          and e.recipientEncryptionKeyVersion = :recipientEncryptionKeyVersion
          and e.vaultId in :vaultIds
          and e.vaultKeyVersion = v.currentVaultKeyVersion
          and e.revokedAt is null
        """)
    List<VaultKeyEnvelope> findCurrentActiveEnvelopesForRecipientAndVaultIds(
            UUID recipientUserId,
            int recipientEncryptionKeyVersion,
            List<UUID> vaultIds
    );
}