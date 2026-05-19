package ru.dmitrysvirgunov.passwordmanager.audit.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.PageRequest;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import ru.dmitrysvirgunov.passwordmanager.audit.config.AuditAnchorStoreProperties;
import ru.dmitrysvirgunov.passwordmanager.audit.entity.AuditAnchorOutbox;
import ru.dmitrysvirgunov.passwordmanager.audit.model.AuditAnchorEnvelope;
import ru.dmitrysvirgunov.passwordmanager.audit.repository.AuditAnchorOutboxRepository;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
public class AuditAnchorExportJob {

    private final AuditAnchorOutboxRepository auditAnchorOutboxRepository;
    private final AuditAnchorStoreClient auditAnchorStoreClient;
    private final AuditAnchorStoreProperties auditAnchorStoreProperties;

    @Scheduled(
            initialDelayString = "${app.audit.anchor-store.initial-delay-ms:15000}",
            fixedDelayString = "${app.audit.anchor-store.interval-ms:30000}"
    )
    public void exportPendingAnchors() {
        if (!auditAnchorStoreClient.isEnabled()) {
            return;
        }

        int batchSize = Math.max(1, auditAnchorStoreProperties.getBatchSize());
        List<AuditAnchorOutbox> batch = auditAnchorOutboxRepository.findByExportedAtIsNullOrderByOutboxIdAsc(
                PageRequest.of(0, batchSize)
        );

        for (AuditAnchorOutbox entry : batch) {
            processEntry(entry);
        }
    }

    private void processEntry(AuditAnchorOutbox entry) {
        entry.setExportAttempts(entry.getExportAttempts() + 1);

        try {
            auditAnchorStoreClient.store(new AuditAnchorEnvelope(
                    entry.getSourceInstanceId(),
                    entry.getScopeType(),
                    entry.getScopeId(),
                    entry.getEventId(),
                    entry.getEventHash(),
                    entry.getEventCreatedAt(),
                    entry.getAnchoredAt(),
                    entry.getAnchorPayload(),
                    entry.getAnchorKeyId(),
                    entry.getAnchorSignature()
            ));

            entry.setExportedAt(normalizeTimestamp(OffsetDateTime.now(ZoneOffset.UTC)));
            entry.setLastError(null);
        } catch (RuntimeException exception) {
            entry.setLastError(abbreviate(exception.getMessage(), 1000));
            log.warn(
                    "Failed to export audit anchor outboxId={}, scopeType={}, scopeId={}, eventId={}",
                    entry.getOutboxId(),
                    entry.getScopeType(),
                    entry.getScopeId(),
                    entry.getEventId(),
                    exception
            );
        }

        auditAnchorOutboxRepository.save(entry);
    }

    private String abbreviate(String value, int maxLength) {
        if (value == null || value.length() <= maxLength) {
            return value;
        }

        return value.substring(0, maxLength);
    }

    private OffsetDateTime normalizeTimestamp(OffsetDateTime value) {
        return value.withOffsetSameInstant(ZoneOffset.UTC)
                .truncatedTo(ChronoUnit.MICROS);
    }
}
