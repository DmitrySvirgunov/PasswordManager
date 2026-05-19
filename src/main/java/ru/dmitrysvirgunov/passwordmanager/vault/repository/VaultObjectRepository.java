package ru.dmitrysvirgunov.passwordmanager.vault.repository;

import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import ru.dmitrysvirgunov.passwordmanager.vault.entity.VaultObject;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface VaultObjectRepository extends JpaRepository<VaultObject, UUID> {

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("""
            select o
            from VaultObject o
            where o.objectId = :objectId
              and o.vaultId = :vaultId
              and o.deleted = false
            """)
    Optional<VaultObject> findForUpdate(
            @Param("objectId") UUID objectId,
            @Param("vaultId") UUID vaultId
    );

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("""
            select o
            from VaultObject o
            where o.vaultId = :vaultId
              and o.deleted = false
            order by o.objectId asc
            """)
    List<VaultObject> findActiveByVaultIdForUpdate(UUID vaultId);

    Optional<VaultObject> findByObjectIdAndVaultId(UUID objectId, UUID vaultId);

    Page<VaultObject> findByVaultIdAndDeletedFalseOrderByUpdatedAtDescObjectIdDesc(
            UUID vaultId,
            Pageable pageable
    );

    Page<VaultObject> findByVaultIdOrderByUpdatedAtDescObjectIdDesc(
            UUID vaultId,
            Pageable pageable
    );

    List<VaultObject> findByVaultIdAndDeletedFalseOrderByUpdatedAtDesc(UUID vaultId);

    List<VaultObject> findByVaultIdOrderByUpdatedAtDesc(UUID vaultId);
}
