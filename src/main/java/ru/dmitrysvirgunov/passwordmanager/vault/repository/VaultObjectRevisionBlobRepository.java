package ru.dmitrysvirgunov.passwordmanager.vault.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import ru.dmitrysvirgunov.passwordmanager.vault.entity.VaultObjectRevisionBlob;
import ru.dmitrysvirgunov.passwordmanager.vault.entity.VaultObjectRevisionBlobId;

import java.util.Collection;
import java.util.List;
import java.util.UUID;

public interface VaultObjectRevisionBlobRepository extends JpaRepository<VaultObjectRevisionBlob, VaultObjectRevisionBlobId> {

    List<VaultObjectRevisionBlob> findByIdRevisionIdOrderByIdRoleAsc(UUID revisionId);

    List<VaultObjectRevisionBlob> findByIdRevisionIdIn(Collection<UUID> revisionIds);

    boolean existsByBlobId(UUID blobId);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query(value = """
            delete from vault_object_revision_blobs revision_blobs
            where revision_blobs.revision_id in (
                select revisions.revision_id
                from vault_object_revisions revisions
                join vault_objects objects
                  on objects.object_id = revisions.object_id
                where objects.vault_id = :vaultId
            )
            """, nativeQuery = true)
    int deleteByVaultId(@Param("vaultId") UUID vaultId);
}
