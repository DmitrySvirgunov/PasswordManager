package ru.dmitrysvirgunov.passwordmanager.vault.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.dmitrysvirgunov.passwordmanager.audit.service.AuditService;
import ru.dmitrysvirgunov.passwordmanager.common.exception.ResourceNotFoundException;
import ru.dmitrysvirgunov.passwordmanager.auth.entity.UserKeyMaterial;
import ru.dmitrysvirgunov.passwordmanager.auth.repository.UserKeyMaterialRepository;
import ru.dmitrysvirgunov.passwordmanager.vault.dto.response.command.CreateVaultResponse;
import ru.dmitrysvirgunov.passwordmanager.vault.entity.Vault;
import ru.dmitrysvirgunov.passwordmanager.vault.entity.VaultKeyEnvelope;
import ru.dmitrysvirgunov.passwordmanager.vault.entity.VaultInvite;
import ru.dmitrysvirgunov.passwordmanager.vault.entity.VaultMember;
import ru.dmitrysvirgunov.passwordmanager.vault.entity.VaultMemberId;
import ru.dmitrysvirgunov.passwordmanager.vault.model.CreateVaultInput;
import ru.dmitrysvirgunov.passwordmanager.vault.model.VaultInviteStatus;
import ru.dmitrysvirgunov.passwordmanager.vault.model.VaultMemberRole;
import ru.dmitrysvirgunov.passwordmanager.vault.model.VaultMemberStatus;
import ru.dmitrysvirgunov.passwordmanager.vault.repository.VaultInviteRepository;
import ru.dmitrysvirgunov.passwordmanager.vault.repository.VaultKeyEnvelopeRepository;
import ru.dmitrysvirgunov.passwordmanager.vault.repository.VaultMemberRepository;
import ru.dmitrysvirgunov.passwordmanager.vault.repository.VaultObjectRevisionBlobRepository;
import ru.dmitrysvirgunov.passwordmanager.vault.repository.VaultRepository;

import java.time.OffsetDateTime;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class VaultCommandService {

    private static final int CURRENT_VAULT_VERSION = 1;
    private static final int CURRENT_VAULT_KEY_VERSION = 1;
    private static final int CURRENT_ENVELOPE_VERSION = 1;

    private final VaultRepository vaultRepository;
    private final VaultMemberRepository vaultMemberRepository;
    private final VaultInviteRepository vaultInviteRepository;
    private final VaultKeyEnvelopeRepository vaultKeyEnvelopeRepository;
    private final UserKeyMaterialRepository userKeyMaterialRepository;
    private final VaultObjectRevisionBlobRepository vaultObjectRevisionBlobRepository;
    private final VaultAccessService vaultAccessService;
    private final VaultSyncService vaultSyncService;
    private final AuditService auditService;

    @Transactional
    public CreateVaultResponse createVault(CreateVaultInput input, Jwt jwt) {
        UUID currentUserId = UUID.fromString(jwt.getSubject());
        UUID vaultId = UUID.randomUUID();
        OffsetDateTime now = OffsetDateTime.now();

        UserKeyMaterial userKeyMaterial = userKeyMaterialRepository.findById(currentUserId)
                .orElseThrow(() -> new ResourceNotFoundException("User key material not found"));

        int recipientEncryptionKeyVersion = userKeyMaterial.getEncryptionKeyVersion();

        Vault vault = Vault.builder()
                .vaultId(vaultId)
                .createdByUserId(currentUserId)
                .nameCiphertext(input.nameCiphertext())
                .nameAeadParams(input.nameAeadParams())
                .vaultVersion(CURRENT_VAULT_VERSION)
                .currentVaultKeyVersion(CURRENT_VAULT_KEY_VERSION)
                .createdAt(now)
                .updatedAt(now)
                .build();

        VaultMember ownerMembership = VaultMember.builder()
                .id(new VaultMemberId(vaultId, currentUserId))
                .role(VaultMemberRole.OWNER)
                .status(VaultMemberStatus.ACTIVE)
                .joinedAt(now)
                .revokedAt(null)
                .expiresAt(null)
                .build();

        VaultKeyEnvelope ownerEnvelope = VaultKeyEnvelope.builder()
                .envelopeId(UUID.randomUUID())
                .vaultId(vaultId)
                .recipientUserId(currentUserId)
                .recipientEncryptionKeyVersion(recipientEncryptionKeyVersion)
                .vaultKeyVersion(CURRENT_VAULT_KEY_VERSION)
                .envelopeVersion(CURRENT_ENVELOPE_VERSION)
                .encryptedVaultKey(input.encryptedVaultKey())
                .envelopeParams(input.envelopeParams())
                .createdByUserId(currentUserId)
                .createdAt(now)
                .revokedAt(null)
                .build();

        vaultRepository.save(vault);
        vaultMemberRepository.save(ownerMembership);
        vaultKeyEnvelopeRepository.save(ownerEnvelope);

        auditService.appendVaultCreated(currentUserId, vaultId, CURRENT_VAULT_VERSION, now);

        return new CreateVaultResponse(vaultId, now);
    }

    @Transactional
    public void deleteVault(UUID vaultId, UUID currentUserId) {
        OffsetDateTime now = OffsetDateTime.now();

        Vault vault = vaultRepository.findByVaultIdForUpdate(vaultId)
                .orElseThrow(() -> new ResourceNotFoundException("Vault not found"));

        vaultAccessService.requireOwnerMembership(vaultId, currentUserId, now);

        List<VaultMember> members = vaultMemberRepository.findByIdVaultIdOrderByJoinedAtAsc(vaultId);
        List<VaultInvite> invites = vaultInviteRepository.findByVaultIdOrderByCreatedAtDesc(vaultId);

        Set<UUID> affectedUserIds = new LinkedHashSet<>();

        for (VaultMember member : members) {
            if (isDeletionNotificationMember(member, now)) {
                affectedUserIds.add(member.getId().getUserId());
            }
        }

        int activeMemberCount = 0;
        for (VaultMember member : members) {
            if (member.getStatus() == VaultMemberStatus.ACTIVE
                    && member.getRevokedAt() == null
                    && (member.getExpiresAt() == null || member.getExpiresAt().isAfter(now))) {
                activeMemberCount++;
            }
        }

        int pendingInviteCount = 0;
        for (VaultInvite invite : invites) {
            if (invite.getStatus() == VaultInviteStatus.PENDING && invite.getRevokedAt() == null) {
                pendingInviteCount++;
                affectedUserIds.add(invite.getInviteeUserId());
            }
        }

        for (UUID targetUserId : affectedUserIds) {
            vaultSyncService.appendTargetedVaultDeleted(
                    vaultId,
                    targetUserId,
                    currentUserId,
                    now
            );
        }

        auditService.appendVaultDeleted(
                currentUserId,
                vaultId,
                affectedUserIds.size(),
                activeMemberCount,
                pendingInviteCount,
                now
        );

        // Links from immutable revisions to blobs are intentionally protected by RESTRICT.
        // When removing the whole vault aggregate, we detach those link rows first so the
        // remaining graph can be safely removed by the database cascades.
        vaultObjectRevisionBlobRepository.deleteByVaultId(vaultId);
        vaultRepository.delete(vault);
    }

    private boolean isDeletionNotificationMember(VaultMember member, OffsetDateTime now) {
        if (member.getRevokedAt() != null) {
            return false;
        }

        if (member.getStatus() != VaultMemberStatus.ACTIVE && member.getStatus() != VaultMemberStatus.INVITED) {
            return false;
        }

        return member.getExpiresAt() == null || member.getExpiresAt().isAfter(now);
    }
}
