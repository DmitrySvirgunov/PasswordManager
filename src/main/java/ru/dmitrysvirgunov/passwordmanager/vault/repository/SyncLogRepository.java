package ru.dmitrysvirgunov.passwordmanager.vault.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import ru.dmitrysvirgunov.passwordmanager.vault.entity.SyncLog;

import java.util.List;
import java.util.UUID;

public interface SyncLogRepository extends JpaRepository<SyncLog, Long> {

    List<SyncLog> findByVaultIdAndSeqGreaterThanOrderBySeqAsc(UUID vaultId, Long seq);

    List<SyncLog> findByTargetUserIdAndSeqGreaterThanOrderBySeqAsc(UUID targetUserId, Long seq);
}
