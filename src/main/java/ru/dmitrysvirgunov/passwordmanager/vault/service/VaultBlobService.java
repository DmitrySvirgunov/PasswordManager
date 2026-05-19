package ru.dmitrysvirgunov.passwordmanager.vault.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.dmitrysvirgunov.passwordmanager.common.exception.ConflictException;
import ru.dmitrysvirgunov.passwordmanager.common.exception.InvalidRequestException;
import ru.dmitrysvirgunov.passwordmanager.common.exception.ResourceNotFoundException;
import ru.dmitrysvirgunov.passwordmanager.vault.dto.response.blob.VaultBlobPartResponse;
import ru.dmitrysvirgunov.passwordmanager.vault.dto.response.blob.VaultBlobResponse;
import ru.dmitrysvirgunov.passwordmanager.vault.dto.response.command.CompleteVaultBlobUploadResponse;
import ru.dmitrysvirgunov.passwordmanager.vault.dto.response.command.CreateVaultBlobResponse;
import ru.dmitrysvirgunov.passwordmanager.vault.entity.VaultBlob;
import ru.dmitrysvirgunov.passwordmanager.vault.entity.VaultBlobPart;
import ru.dmitrysvirgunov.passwordmanager.vault.entity.VaultBlobPartId;
import ru.dmitrysvirgunov.passwordmanager.vault.model.CompleteVaultBlobUploadInput;
import ru.dmitrysvirgunov.passwordmanager.vault.model.CreateVaultBlobInput;
import ru.dmitrysvirgunov.passwordmanager.vault.model.UploadVaultBlobPartInput;
import ru.dmitrysvirgunov.passwordmanager.vault.model.VaultBlobStatus;
import ru.dmitrysvirgunov.passwordmanager.vault.repository.VaultBlobPartRepository;
import ru.dmitrysvirgunov.passwordmanager.vault.repository.VaultBlobRepository;
import ru.dmitrysvirgunov.passwordmanager.vault.repository.VaultObjectRevisionBlobRepository;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.OffsetDateTime;
import java.util.Arrays;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class VaultBlobService {

    private static final int MAX_BLOB_CHUNK_SIZE_BYTES = 4 * 1024 * 1024 + 16;
    private static final int MAX_BLOB_CHUNK_COUNT = 10_000;

    private final VaultBlobRepository vaultBlobRepository;
    private final VaultBlobPartRepository vaultBlobPartRepository;
    private final VaultObjectRevisionBlobRepository vaultObjectRevisionBlobRepository;
    private final VaultAccessService vaultAccessService;
    private final VaultBlobTelemetryService vaultBlobTelemetryService;

    @Transactional
    public CreateVaultBlobResponse createBlob(UUID vaultId, CreateVaultBlobInput input, Jwt jwt) {
        UUID currentUserId = UUID.fromString(jwt.getSubject());
        OffsetDateTime now = OffsetDateTime.now();

        vaultAccessService.requireWritableMembership(vaultId, currentUserId, now);
        validateCreateBlobInput(input);

        UUID blobId = UUID.randomUUID();
        VaultBlob blob = VaultBlob.builder()
                .blobId(blobId)
                .vaultId(vaultId)
                .status(VaultBlobStatus.PENDING)
                .ciphertextSizeBytes(input.ciphertextSizeBytes())
                .chunkSizeBytes(input.chunkSizeBytes())
                .chunkCount(input.chunkCount())
                .createdByUserId(currentUserId)
                .createdAt(now)
                .build();

        vaultBlobRepository.save(blob);

        return new CreateVaultBlobResponse(
                blobId,
                blob.getStatus(),
                now
        );
    }

    @Transactional
    public void uploadBlobPart(
            UUID vaultId,
            UUID blobId,
            int partNumber,
            UploadVaultBlobPartInput input,
            Jwt jwt
    ) {
        UUID currentUserId = UUID.fromString(jwt.getSubject());
        OffsetDateTime now = OffsetDateTime.now();

        vaultAccessService.requireWritableMembership(vaultId, currentUserId, now);

        VaultBlob blob = loadBlobForUpdateOrThrow(vaultId, blobId);
        validatePendingBlob(blob);

        if (partNumber > blob.getChunkCount()) {
            throw new InvalidRequestException(
                    "partNumber must not exceed blob chunkCount " + blob.getChunkCount()
            );
        }

        if (!Arrays.equals(sha256(input.ciphertextChunk()), input.ciphertextChunkSha256())) {
            throw new InvalidRequestException("ciphertextChunkSha256 does not match ciphertextChunk");
        }

        if (input.ciphertextChunk().length > blob.getChunkSizeBytes()) {
            throw new InvalidRequestException(
                    "ciphertextChunk exceeds declared chunkSizeBytes " + blob.getChunkSizeBytes()
            );
        }

        if (input.ciphertextChunk().length > MAX_BLOB_CHUNK_SIZE_BYTES) {
            throw new InvalidRequestException(
                    "ciphertextChunk exceeds max supported chunk size " + MAX_BLOB_CHUNK_SIZE_BYTES
            );
        }

        VaultBlobPart part = VaultBlobPart.builder()
                .id(new VaultBlobPartId(blobId, partNumber))
                .ciphertext(input.ciphertextChunk())
                .ciphertextSha256(input.ciphertextChunkSha256())
                .ciphertextSizeBytes(input.ciphertextChunk().length)
                .createdAt(now)
                .build();

        vaultBlobPartRepository.save(part);
    }

    @Transactional
    public CompleteVaultBlobUploadResponse completeBlobUpload(
            UUID vaultId,
            UUID blobId,
            CompleteVaultBlobUploadInput input,
            Jwt jwt
    ) {
        UUID currentUserId = UUID.fromString(jwt.getSubject());
        OffsetDateTime now = OffsetDateTime.now();

        vaultAccessService.requireWritableMembership(vaultId, currentUserId, now);

        VaultBlob blob = loadBlobForUpdateOrThrow(vaultId, blobId);
        validatePendingBlob(blob);

        long uploadedPartCount = vaultBlobPartRepository.countByIdBlobId(blobId);

        if (uploadedPartCount != blob.getChunkCount()) {
            throw new ConflictException(
                    "Blob part count mismatch: expected " + blob.getChunkCount()
                            + ", but uploaded " + uploadedPartCount
            );
        }

        long totalCiphertextSize = 0;
        MessageDigest digest = newSha256Digest();

        for (int partNumber = 1; partNumber <= blob.getChunkCount(); partNumber += 1) {
            int currentPartNumber = partNumber;
            VaultBlobPartRepository.CiphertextPartView part =
                    vaultBlobPartRepository.findCiphertextPart(blobId, currentPartNumber)
                            .orElseThrow(() -> new ConflictException("Blob is missing part " + currentPartNumber));

            totalCiphertextSize += part.getCiphertextSizeBytes();
            digest.update(part.getCiphertext());
        }

        if (totalCiphertextSize != blob.getCiphertextSizeBytes()) {
            throw new ConflictException(
                    "Blob ciphertext size mismatch: expected " + blob.getCiphertextSizeBytes()
                            + ", but uploaded " + totalCiphertextSize
            );
        }

        byte[] actualCiphertextSha256 = digest.digest();

        if (!Arrays.equals(actualCiphertextSha256, input.ciphertextSha256())) {
            throw new ConflictException("Blob ciphertext SHA-256 mismatch");
        }

        blob.setCiphertextSha256(actualCiphertextSha256);
        blob.setStatus(VaultBlobStatus.READY);
        blob.setCompletedAt(now);
        vaultBlobRepository.save(blob);

        return new CompleteVaultBlobUploadResponse(
                blobId,
                blob.getStatus(),
                now
        );
    }

    @Transactional(readOnly = true)
    public VaultBlobResponse getBlob(UUID vaultId, UUID blobId, Jwt jwt) {
        UUID currentUserId = UUID.fromString(jwt.getSubject());
        OffsetDateTime now = OffsetDateTime.now();

        vaultAccessService.requireReadableMembership(vaultId, currentUserId, now);

        VaultBlob blob = vaultBlobRepository.findByBlobIdAndVaultId(blobId, vaultId)
                .orElseThrow(() -> new ResourceNotFoundException("Vault blob not found"));

        return new VaultBlobResponse(
                blob.getBlobId(),
                blob.getStatus(),
                blob.getCiphertextSizeBytes(),
                blob.getChunkSizeBytes(),
                blob.getChunkCount(),
                vaultBlobPartRepository.countByIdBlobId(blobId),
                blob.getCreatedAt(),
                blob.getCompletedAt()
        );
    }

    @Transactional(readOnly = true)
    public VaultBlobPartResponse getBlobPart(UUID vaultId, UUID blobId, int partNumber, Jwt jwt) {
        UUID currentUserId = UUID.fromString(jwt.getSubject());
        OffsetDateTime now = OffsetDateTime.now();

        vaultAccessService.requireReadableMembership(vaultId, currentUserId, now);

        VaultBlob blob = vaultBlobRepository.findByBlobIdAndVaultId(blobId, vaultId)
                .orElseThrow(() -> new ResourceNotFoundException("Vault blob not found"));

        if (blob.getStatus() != VaultBlobStatus.READY) {
            throw new ConflictException("Vault blob is not ready");
        }

        VaultBlobPartRepository.CiphertextPartView part = vaultBlobPartRepository.findCiphertextPart(blobId, partNumber)
                .orElseThrow(() -> new ResourceNotFoundException("Vault blob part not found"));

        return new VaultBlobPartResponse(
                blobId,
                partNumber,
                part.getCiphertext(),
                part.getCiphertextSha256(),
                part.getCiphertextSizeBytes()
        );
    }

    @Transactional(readOnly = true)
    public VaultBlob requireReadyBlob(UUID vaultId, UUID blobId) {
        VaultBlob blob = vaultBlobRepository.findByBlobIdAndVaultId(blobId, vaultId)
                .orElseThrow(() -> new ResourceNotFoundException("Vault blob not found"));

        if (blob.getStatus() != VaultBlobStatus.READY) {
            throw new ConflictException("Vault blob " + blobId + " is not ready");
        }

        return blob;
    }

    @Transactional
    public VaultBlob requireReadyBlobForReference(UUID vaultId, UUID blobId) {
        VaultBlob blob = loadBlobForUpdateOrThrow(vaultId, blobId);

        if (blob.getStatus() != VaultBlobStatus.READY) {
            throw new ConflictException("Vault blob " + blobId + " is not ready");
        }

        return blob;
    }

    @Transactional
    public void abortBlob(UUID vaultId, UUID blobId, Jwt jwt) {
        UUID currentUserId = UUID.fromString(jwt.getSubject());
        OffsetDateTime now = OffsetDateTime.now();

        vaultAccessService.requireWritableMembership(vaultId, currentUserId, now);
        vaultBlobTelemetryService.recordClientAbortRequested();

        try {
            boolean changedState = abortBlobIfUnreferenced(vaultId, blobId);
            vaultBlobTelemetryService.recordClientAbortSucceeded(changedState);
        } catch (ConflictException exception) {
            vaultBlobTelemetryService.recordClientAbortConflict();
            throw exception;
        } catch (RuntimeException exception) {
            vaultBlobTelemetryService.recordClientAbortFailure();
            throw exception;
        }
    }

    @Transactional
    public boolean abortBlobIfUnreferenced(UUID vaultId, UUID blobId) {
        VaultBlob blob = loadBlobForUpdateOrThrow(vaultId, blobId);

        if (vaultObjectRevisionBlobRepository.existsByBlobId(blobId)) {
            throw new ConflictException("Vault blob " + blobId + " is already referenced by a record revision");
        }

        if (blob.getStatus() == VaultBlobStatus.ABORTED) {
            return false;
        }

        blob.setStatus(VaultBlobStatus.ABORTED);
        vaultBlobPartRepository.deleteByIdBlobId(blobId);
        vaultBlobRepository.save(blob);
        return true;
    }

    private VaultBlob loadBlobForUpdateOrThrow(UUID vaultId, UUID blobId) {
        return vaultBlobRepository.findForUpdate(blobId, vaultId)
                .orElseThrow(() -> new ResourceNotFoundException("Vault blob not found"));
    }

    private void validatePendingBlob(VaultBlob blob) {
        if (blob.getStatus() != VaultBlobStatus.PENDING) {
            throw new ConflictException("Vault blob is not pending");
        }
    }

    private void validateCreateBlobInput(CreateVaultBlobInput input) {
        if (input.chunkSizeBytes() > MAX_BLOB_CHUNK_SIZE_BYTES) {
            throw new InvalidRequestException(
                    "chunkSizeBytes must not exceed " + MAX_BLOB_CHUNK_SIZE_BYTES
            );
        }

        if (input.chunkCount() > MAX_BLOB_CHUNK_COUNT) {
            throw new InvalidRequestException(
                    "chunkCount must not exceed " + MAX_BLOB_CHUNK_COUNT
            );
        }

        long maxAddressableBytes = (long) input.chunkSizeBytes() * input.chunkCount();

        if (maxAddressableBytes < input.ciphertextSizeBytes()) {
            throw new InvalidRequestException(
                    "chunkSizeBytes * chunkCount must cover ciphertextSizeBytes"
            );
        }

        if (input.chunkCount() == 1 && input.chunkSizeBytes() < input.ciphertextSizeBytes()) {
            throw new InvalidRequestException(
                    "chunkSizeBytes must be at least ciphertextSizeBytes when chunkCount is 1"
            );
        }
    }

    private byte[] sha256(byte[] bytes) {
        MessageDigest digest = newSha256Digest();
        digest.update(bytes);
        return digest.digest();
    }

    private MessageDigest newSha256Digest() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }
}
