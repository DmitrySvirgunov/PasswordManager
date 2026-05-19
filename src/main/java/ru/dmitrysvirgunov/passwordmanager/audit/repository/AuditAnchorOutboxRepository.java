package ru.dmitrysvirgunov.passwordmanager.audit.repository;

import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import ru.dmitrysvirgunov.passwordmanager.audit.entity.AuditAnchorOutbox;

import java.util.List;

public interface AuditAnchorOutboxRepository extends JpaRepository<AuditAnchorOutbox, Long> {

    List<AuditAnchorOutbox> findByExportedAtIsNullOrderByOutboxIdAsc(Pageable pageable);
}
