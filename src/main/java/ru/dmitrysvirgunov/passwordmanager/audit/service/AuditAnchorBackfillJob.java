package ru.dmitrysvirgunov.passwordmanager.audit.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.PageRequest;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import ru.dmitrysvirgunov.passwordmanager.audit.config.AuditAnchorStoreProperties;
import ru.dmitrysvirgunov.passwordmanager.audit.entity.AuditEvent;
import ru.dmitrysvirgunov.passwordmanager.audit.repository.AuditEventRepository;

import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
public class AuditAnchorBackfillJob {

    private final AuditAnchorService auditAnchorService;
    private final AuditAnchorStoreProperties auditAnchorStoreProperties;
    private final AuditEventRepository auditEventRepository;

    @Scheduled(
            initialDelayString = "${app.audit.anchor-store.initial-delay-ms:15000}",
            fixedDelayString = "${app.audit.anchor-store.interval-ms:30000}"
    )
    public void backfillCurrentScopeHeadsIntoOutbox() {
        int batchSize = Math.max(1, auditAnchorStoreProperties.getBatchSize());
        List<AuditEvent> missingHeads = auditEventRepository.findHeadEventsMissingAnchorOutbox(
                auditAnchorStoreProperties.getSourceInstanceId(),
                PageRequest.of(0, batchSize)
        );

        for (AuditEvent event : missingHeads) {
            try {
                auditAnchorService.enqueueAnchor(event);
            } catch (DataIntegrityViolationException exception) {
                log.debug(
                        "Skipped duplicate audit anchor outbox entry for scopeType={}, scopeId={}, eventId={}",
                        event.getScopeType(),
                        event.getScopeId(),
                        event.getEventId()
                );
            }
        }
    }
}
