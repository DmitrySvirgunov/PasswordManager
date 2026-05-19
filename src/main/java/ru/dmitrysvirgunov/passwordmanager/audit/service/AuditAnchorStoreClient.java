package ru.dmitrysvirgunov.passwordmanager.audit.service;

import ru.dmitrysvirgunov.passwordmanager.audit.model.AuditAnchorEnvelope;
import ru.dmitrysvirgunov.passwordmanager.audit.model.AuditScopeType;

import java.util.Optional;
import java.util.UUID;

public interface AuditAnchorStoreClient {

    boolean isEnabled();

    void store(AuditAnchorEnvelope anchor);

    Optional<AuditAnchorEnvelope> findLatestAnchor(AuditScopeType scopeType, UUID scopeId);
}
