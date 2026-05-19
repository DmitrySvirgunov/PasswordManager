package ru.dmitrysvirgunov.passwordmanager.vault.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import ru.dmitrysvirgunov.passwordmanager.vault.entity.VaultInvite;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface VaultInviteRepository extends JpaRepository<VaultInvite, UUID> {

    List<VaultInvite> findByVaultIdOrderByCreatedAtDesc(UUID vaultId);

    Optional<VaultInvite> findByInviteIdAndInviteeUserId(UUID inviteId, UUID inviteeUserId);

    Optional<VaultInvite> findByInviteIdAndVaultId(UUID inviteId, UUID vaultId);

    List<VaultInvite> findByInviteeUserIdOrderByCreatedAtDesc(UUID inviteeUserId);
}