package ru.dmitrysvirgunov.passwordmanager.audit.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.dmitrysvirgunov.passwordmanager.audit.entity.AuditEvent;
import ru.dmitrysvirgunov.passwordmanager.audit.model.AuditEventVerificationResult;
import ru.dmitrysvirgunov.passwordmanager.audit.repository.AuditEventRepository;

import java.util.List;
import java.util.Arrays;

@Service
@RequiredArgsConstructor
public class AuditVerificationService {

    private final AuditEventRepository auditEventRepository;
    private final AuditHashService auditHashService;
    private final AuditVerificationKeyService auditVerificationKeyService;

    @Transactional(readOnly = true)
    public AuditEventVerificationResult verifyEvent(Long eventId) {
        AuditEvent event = auditEventRepository.findById(eventId)
                .orElseThrow(() -> new IllegalStateException("Audit event not found: " + eventId));

        List<AuditEvent> scopeEvents = auditEventRepository.findByScopeTypeAndScopeIdOrderByEventIdAsc(
                event.getScopeType(),
                event.getScopeId()
        );

        byte[] expectedPrevHash = null;
        boolean chainValidSoFar = true;

        for (AuditEvent scopeEvent : scopeEvents) {
            boolean prevLinkValid = Arrays.equals(scopeEvent.getPrevEventHash(), expectedPrevHash);

            byte[] recomputedHash = auditHashService.computeEventHash(
                    scopeEvent.getActorUserId(),
                    scopeEvent.getScopeType(),
                    scopeEvent.getScopeId(),
                    scopeEvent.getEventType(),
                    scopeEvent.getMeta(),
                    scopeEvent.getCreatedAt(),
                    expectedPrevHash
            );

            boolean hashValid = Arrays.equals(scopeEvent.getEventHash(), recomputedHash);
            boolean signatureValid = auditVerificationKeyService.verify(
                    scopeEvent.getSignatureKeyId(),
                    scopeEvent.getEventHash(),
                    scopeEvent.getEventSignature()
            );
            boolean localValid = prevLinkValid && hashValid && signatureValid;
            boolean chainValid = chainValidSoFar && localValid;

            if (scopeEvent.getEventId().equals(eventId)) {
                return new AuditEventVerificationResult(
                        scopeEvent.getEventId(),
                        scopeEvent.getScopeType(),
                        scopeEvent.getScopeId(),
                        scopeEvent.getEventType(),
                        chainValid,
                        prevLinkValid,
                        hashValid,
                        signatureValid,
                        chainValid
                );
            }

            expectedPrevHash = scopeEvent.getEventHash();
            chainValidSoFar = chainValid;
        }

        throw new IllegalStateException("Audit event not found in scope chain: " + eventId);
    }
}
