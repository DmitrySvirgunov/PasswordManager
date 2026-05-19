package ru.dmitrysvirgunov.passwordmanager.vault.service;

import org.springframework.stereotype.Service;

import java.time.OffsetDateTime;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.atomic.LongAdder;

@Service
public class VaultBlobTelemetryService {

    private final LongAdder clientAbortRequests = new LongAdder();
    private final LongAdder clientAbortSucceeded = new LongAdder();
    private final LongAdder clientAbortNoop = new LongAdder();
    private final LongAdder clientAbortConflicts = new LongAdder();
    private final LongAdder clientAbortFailures = new LongAdder();

    private final LongAdder cleanupRuns = new LongAdder();
    private final LongAdder cleanupPendingCandidates = new LongAdder();
    private final LongAdder cleanupReadyCandidates = new LongAdder();
    private final LongAdder cleanupPendingCleaned = new LongAdder();
    private final LongAdder cleanupReadyCleaned = new LongAdder();
    private final LongAdder cleanupSkippedStateChanges = new LongAdder();
    private final LongAdder cleanupFailures = new LongAdder();

    private final AtomicReference<OffsetDateTime> lastCleanupAt = new AtomicReference<>();

    public void recordClientAbortRequested() {
        clientAbortRequests.increment();
    }

    public void recordClientAbortSucceeded(boolean changedState) {
        if (changedState) {
            clientAbortSucceeded.increment();
            return;
        }

        clientAbortNoop.increment();
    }

    public void recordClientAbortConflict() {
        clientAbortConflicts.increment();
    }

    public void recordClientAbortFailure() {
        clientAbortFailures.increment();
    }

    public void recordCleanupRun(
            int pendingCandidates,
            int readyCandidates,
            int cleanedPending,
            int cleanedReady,
            int skippedStateChanges,
            int failures
    ) {
        cleanupRuns.increment();
        cleanupPendingCandidates.add(pendingCandidates);
        cleanupReadyCandidates.add(readyCandidates);
        cleanupPendingCleaned.add(cleanedPending);
        cleanupReadyCleaned.add(cleanedReady);
        cleanupSkippedStateChanges.add(skippedStateChanges);
        cleanupFailures.add(failures);
        lastCleanupAt.set(OffsetDateTime.now());
    }

    public String formatSummary() {
        OffsetDateTime lastCleanup = lastCleanupAt.get();

        return "clientAbortRequests=" + clientAbortRequests.sum()
                + ", clientAbortSucceeded=" + clientAbortSucceeded.sum()
                + ", clientAbortNoop=" + clientAbortNoop.sum()
                + ", clientAbortConflicts=" + clientAbortConflicts.sum()
                + ", clientAbortFailures=" + clientAbortFailures.sum()
                + ", cleanupRuns=" + cleanupRuns.sum()
                + ", cleanupPendingCandidates=" + cleanupPendingCandidates.sum()
                + ", cleanupReadyCandidates=" + cleanupReadyCandidates.sum()
                + ", cleanupPendingCleaned=" + cleanupPendingCleaned.sum()
                + ", cleanupReadyCleaned=" + cleanupReadyCleaned.sum()
                + ", cleanupSkippedStateChanges=" + cleanupSkippedStateChanges.sum()
                + ", cleanupFailures=" + cleanupFailures.sum()
                + ", lastCleanupAt=" + (lastCleanup == null ? "never" : lastCleanup);
    }
}
