package ru.dmitrysvirgunov.passwordmanager.vault.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.PageRequest;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import ru.dmitrysvirgunov.passwordmanager.common.exception.ConflictException;
import ru.dmitrysvirgunov.passwordmanager.common.exception.ResourceNotFoundException;
import ru.dmitrysvirgunov.passwordmanager.vault.config.VaultBlobCleanupProperties;
import ru.dmitrysvirgunov.passwordmanager.vault.entity.VaultBlob;
import ru.dmitrysvirgunov.passwordmanager.vault.repository.VaultBlobRepository;

import java.time.OffsetDateTime;
import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
public class VaultBlobCleanupJob {

    private final VaultBlobCleanupProperties properties;
    private final VaultBlobRepository vaultBlobRepository;
    private final VaultBlobService vaultBlobService;
    private final VaultBlobTelemetryService vaultBlobTelemetryService;

    @Scheduled(
            initialDelayString = "${app.vault.blob-cleanup.initial-delay-ms:300000}",
            fixedDelayString = "${app.vault.blob-cleanup.interval-ms:600000}"
    )
    public void cleanupStaleUnreferencedBlobs() {
        if (!properties.isEnabled()) {
            return;
        }

        int batchSize = Math.max(1, properties.getBatchSize());
        OffsetDateTime now = OffsetDateTime.now();
        List<VaultBlob> pendingCandidates = vaultBlobRepository.findStaleUnreferencedPendingBlobs(
                now.minus(properties.getPendingMaxAge()),
                PageRequest.of(0, batchSize)
        );
        List<VaultBlob> readyCandidates = vaultBlobRepository.findStaleUnreferencedReadyBlobs(
                now.minus(properties.getReadyMaxAge()),
                PageRequest.of(0, batchSize)
        );

        CleanupBatchResult pendingResult = cleanupBatch(
                "pending",
                pendingCandidates
        );
        CleanupBatchResult readyResult = cleanupBatch(
                "ready",
                readyCandidates
        );

        vaultBlobTelemetryService.recordCleanupRun(
                pendingCandidates.size(),
                readyCandidates.size(),
                pendingResult.cleaned(),
                readyResult.cleaned(),
                pendingResult.skippedStateChanges() + readyResult.skippedStateChanges(),
                pendingResult.failures() + readyResult.failures()
        );

        log.info(
                "Vault blob cleanup run: pendingCandidates={}, readyCandidates={}, cleanedPending={}, cleanedReady={}, skippedStateChanges={}, failures={} | {}",
                pendingCandidates.size(),
                readyCandidates.size(),
                pendingResult.cleaned(),
                readyResult.cleaned(),
                pendingResult.skippedStateChanges() + readyResult.skippedStateChanges(),
                pendingResult.failures() + readyResult.failures(),
                vaultBlobTelemetryService.formatSummary()
        );
    }

    private CleanupBatchResult cleanupBatch(String label, List<VaultBlob> candidates) {
        int cleaned = 0;
        int skippedStateChanges = 0;
        int failures = 0;

        for (VaultBlob blob : candidates) {
            try {
                if (vaultBlobService.abortBlobIfUnreferenced(blob.getVaultId(), blob.getBlobId())) {
                    cleaned += 1;
                } else {
                    skippedStateChanges += 1;
                }
            } catch (ConflictException | ResourceNotFoundException exception) {
                skippedStateChanges += 1;
                log.debug(
                        "Skipped {} orphan cleanup candidate blobId={} because state changed: {}",
                        label,
                        blob.getBlobId(),
                        exception.getMessage()
                );
            } catch (RuntimeException exception) {
                failures += 1;
                log.warn(
                        "Failed to clean up {} orphan blobId={}",
                        label,
                        blob.getBlobId(),
                        exception
                );
            }
        }

        return new CleanupBatchResult(cleaned, skippedStateChanges, failures);
    }

    private record CleanupBatchResult(
            int cleaned,
            int skippedStateChanges,
            int failures
    ) {
    }
}
