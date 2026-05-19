package ru.dmitrysvirgunov.passwordmanager.audit.entity;

import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import ru.dmitrysvirgunov.passwordmanager.audit.model.AuditScopeType;

import java.io.Serializable;
import java.util.UUID;

@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode
public class AuditScopeHeadId implements Serializable {

    private AuditScopeType scopeType;
    private UUID scopeId;
}
