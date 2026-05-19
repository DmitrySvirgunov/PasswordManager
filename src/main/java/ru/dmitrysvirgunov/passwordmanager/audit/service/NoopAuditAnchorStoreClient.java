package ru.dmitrysvirgunov.passwordmanager.audit.service;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.stereotype.Component;
import ru.dmitrysvirgunov.passwordmanager.audit.model.AuditAnchorEnvelope;
import ru.dmitrysvirgunov.passwordmanager.audit.model.AuditScopeType;

import java.util.Optional;
import java.util.UUID;

@Component
@ConditionalOnMissingBean(AuditAnchorStoreClient.class)
public class NoopAuditAnchorStoreClient implements AuditAnchorStoreClient {

    @Override
    public boolean isEnabled() {
        return false;
    }

    @Override
    public void store(AuditAnchorEnvelope anchor) {
    }

    @Override
    public Optional<AuditAnchorEnvelope> findLatestAnchor(AuditScopeType scopeType, UUID scopeId) {
        return Optional.empty();
    }
}
