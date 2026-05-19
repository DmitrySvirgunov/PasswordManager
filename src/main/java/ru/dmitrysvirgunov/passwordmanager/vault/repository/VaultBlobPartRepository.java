package ru.dmitrysvirgunov.passwordmanager.vault.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import ru.dmitrysvirgunov.passwordmanager.vault.entity.VaultBlobPart;
import ru.dmitrysvirgunov.passwordmanager.vault.entity.VaultBlobPartId;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface VaultBlobPartRepository extends JpaRepository<VaultBlobPart, VaultBlobPartId> {

    interface CiphertextPartView {
        byte[] getCiphertext();

        byte[] getCiphertextSha256();

        int getCiphertextSizeBytes();
    }

    List<VaultBlobPart> findByIdBlobIdOrderByIdPartNumberAsc(UUID blobId);

    Optional<VaultBlobPart> findByIdBlobIdAndIdPartNumber(UUID blobId, int partNumber);

    @Query("""
            select p.ciphertext as ciphertext,
                   p.ciphertextSha256 as ciphertextSha256,
                   p.ciphertextSizeBytes as ciphertextSizeBytes
            from VaultBlobPart p
            where p.id.blobId = :blobId
              and p.id.partNumber = :partNumber
            """)
    Optional<CiphertextPartView> findCiphertextPart(
            @Param("blobId") UUID blobId,
            @Param("partNumber") int partNumber
    );

    long countByIdBlobId(UUID blobId);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("""
            delete from VaultBlobPart p
            where p.id.blobId = :blobId
            """)
    int deleteByIdBlobId(@Param("blobId") UUID blobId);

    @Query("""
            select coalesce(sum(p.ciphertextSizeBytes), 0)
            from VaultBlobPart p
            where p.id.blobId = :blobId
            """)
    long sumCiphertextSizeBytesByBlobId(@Param("blobId") UUID blobId);
}
