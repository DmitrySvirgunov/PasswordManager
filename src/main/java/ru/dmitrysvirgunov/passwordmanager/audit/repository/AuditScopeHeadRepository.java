package ru.dmitrysvirgunov.passwordmanager.audit.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import ru.dmitrysvirgunov.passwordmanager.audit.entity.AuditScopeHead;
import ru.dmitrysvirgunov.passwordmanager.audit.entity.AuditScopeHeadId;

public interface AuditScopeHeadRepository extends JpaRepository<AuditScopeHead, AuditScopeHeadId> {
}
