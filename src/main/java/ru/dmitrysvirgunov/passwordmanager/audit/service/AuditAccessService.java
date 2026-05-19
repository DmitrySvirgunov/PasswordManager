package ru.dmitrysvirgunov.passwordmanager.audit.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.dmitrysvirgunov.passwordmanager.audit.entity.AuditEvent;
import ru.dmitrysvirgunov.passwordmanager.audit.model.AuditScopeType;
import ru.dmitrysvirgunov.passwordmanager.audit.repository.AuditEventRepository;
import ru.dmitrysvirgunov.passwordmanager.common.exception.ApplicationAccessDeniedException;
import ru.dmitrysvirgunov.passwordmanager.common.exception.ResourceNotFoundException;
import ru.dmitrysvirgunov.passwordmanager.vault.service.VaultAccessService;

import java.time.OffsetDateTime;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuditAccessService {

    private final AuditEventRepository auditEventRepository;
    private final VaultAccessService vaultAccessService;

    @Transactional(readOnly = true)
    public void requireVaultAuditRead(UUID vaultId, Jwt jwt) {
        UUID currentUserId = UUID.fromString(jwt.getSubject());
        vaultAccessService.requireReadableMembership(vaultId, currentUserId, OffsetDateTime.now());
    }

    @Transactional(readOnly = true)
    public void requireUserAuditRead(UUID userId, Jwt jwt) {
        UUID currentUserId = UUID.fromString(jwt.getSubject());

        if (!currentUserId.equals(userId)) {
            throw new ApplicationAccessDeniedException("Access to user audit denied");
        }
    }

    @Transactional(readOnly = true)
    public void requireEventAuditRead(Long eventId, Jwt jwt) {
        AuditEvent event = auditEventRepository.findById(eventId)
                .orElseThrow(() -> new ResourceNotFoundException("Audit event not found"));

        if (event.getScopeType() == AuditScopeType.VAULT) {
            requireVaultAuditRead(event.getScopeId(), jwt);
            return;
        }

        if (event.getScopeType() == AuditScopeType.USER) {
            requireUserAuditRead(event.getScopeId(), jwt);
            return;
        }

        throw new ApplicationAccessDeniedException("Unsupported audit scope");
    }
}