package ru.dmitrysvirgunov.passwordmanager.vault.repository;

import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.domain.Pageable;
import org.springframework.data.repository.query.Param;
import ru.dmitrysvirgunov.passwordmanager.vault.entity.VaultBlob;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface VaultBlobRepository extends JpaRepository<VaultBlob, UUID> {

    Optional<VaultBlob> findByBlobIdAndVaultId(UUID blobId, UUID vaultId);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("""
            select b
            from VaultBlob b
            where b.blobId = :blobId
              and b.vaultId = :vaultId
            """)
    Optional<VaultBlob> findForUpdate(
            @Param("blobId") UUID blobId,
            @Param("vaultId") UUID vaultId
    );

    @Query("""
            select b
            from VaultBlob b
            where b.status = ru.dmitrysvirgunov.passwordmanager.vault.model.VaultBlobStatus.PENDING
              and b.createdAt <= :cutoff
              and not exists (
                    select 1
                    from VaultObjectRevisionBlob revisionBlob
                    where revisionBlob.blobId = b.blobId
              )
            order by b.createdAt asc
            """)
    List<VaultBlob> findStaleUnreferencedPendingBlobs(
            @Param("cutoff") OffsetDateTime cutoff,
            Pageable pageable
    );

    @Query("""
            select b
            from VaultBlob b
            where b.status = ru.dmitrysvirgunov.passwordmanager.vault.model.VaultBlobStatus.READY
              and b.completedAt is not null
              and b.completedAt <= :cutoff
              and not exists (
                    select 1
                    from VaultObjectRevisionBlob revisionBlob
                    where revisionBlob.blobId = b.blobId
              )
            order by b.completedAt asc
            """)
    List<VaultBlob> findStaleUnreferencedReadyBlobs(
            @Param("cutoff") OffsetDateTime cutoff,
            Pageable pageable
    );
}
