package ru.dmitrysvirgunov.passwordmanager.vault.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.dmitrysvirgunov.passwordmanager.auth.entity.User;
import ru.dmitrysvirgunov.passwordmanager.auth.entity.UserKeyMaterial;
import ru.dmitrysvirgunov.passwordmanager.auth.model.UserStatus;
import ru.dmitrysvirgunov.passwordmanager.auth.repository.UserKeyMaterialRepository;
import ru.dmitrysvirgunov.passwordmanager.auth.repository.UserRepository;
import ru.dmitrysvirgunov.passwordmanager.common.exception.ConflictException;
import ru.dmitrysvirgunov.passwordmanager.common.exception.ResourceNotFoundException;
import ru.dmitrysvirgunov.passwordmanager.vault.dto.response.command.CreateVaultInviteResponse;
import ru.dmitrysvirgunov.passwordmanager.vault.entity.*;
import ru.dmitrysvirgunov.passwordmanager.vault.model.*;
import ru.dmitrysvirgunov.passwordmanager.vault.repository.VaultInviteRepository;
import ru.dmitrysvirgunov.passwordmanager.vault.repository.VaultKeyEnvelopeRepository;
import ru.dmitrysvirgunov.passwordmanager.vault.repository.VaultMemberRepository;
import ru.dmitrysvirgunov.passwordmanager.vault.repository.VaultRepository;
import ru.dmitrysvirgunov.passwordmanager.audit.service.AuditService;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
    public class VaultSharingService {

    private static final int CURRENT_ENVELOPE_VERSION = 1;

    private final VaultRepository vaultRepository;
    private final VaultMemberRepository vaultMemberRepository;
    private final VaultInviteRepository vaultInviteRepository;
    private final VaultKeyEnvelopeRepository vaultKeyEnvelopeRepository;
    private final UserRepository userRepository;
    private final UserKeyMaterialRepository userKeyMaterialRepository;
    private final VaultAccessService vaultAccessService;
    private final VaultSharingAntiAbuseService vaultSharingAntiAbuseService;
    private final VaultSyncService vaultSyncService;
    private final AuditService auditService;

    @Transactional
    public CreateVaultInviteResponse createInvite(
            UUID vaultId,
            CreateVaultInviteInput input,
            UUID currentUserId
    ) {
        OffsetDateTime now = OffsetDateTime.now();

        validateInviteCreationAccess(vaultId, currentUserId, now);
        vaultSharingAntiAbuseService.checkCreateInviteAllowed(
                currentUserId,
                vaultId,
                input.inviteeEmail()
        );

        Vault vault = loadVaultOrThrow(vaultId);
        User invitee = loadInviteeOrThrow(input.inviteeEmail());
        validateInvitee(vaultId, input, currentUserId, invitee);

        UserKeyMaterial inviteeKeyMaterial = loadInviteeKeyMaterialOrThrow(invitee.getUserId());
        VaultMember membership = prepareMembershipForInvite(vaultId, invitee.getUserId(), input.role(), now);

        OffsetDateTime expiresAt = now.plusDays(7);
        UUID inviteId = UUID.randomUUID();

        VaultInvite invite = buildInvite(
                inviteId,
                vaultId,
                currentUserId,
                invitee,
                input.role(),
                now,
                expiresAt
        );

        VaultKeyEnvelope envelope = buildInviteEnvelope(
                vaultId,
                currentUserId,
                invitee.getUserId(),
                inviteeKeyMaterial.getEncryptionKeyVersion(),
                vault.getCurrentVaultKeyVersion(),
                input,
                now
        );

        vaultInviteRepository.save(invite);
        vaultMemberRepository.save(membership);
        vaultKeyEnvelopeRepository.save(envelope);

        vaultSyncService.appendTargetedMembershipChanged(
                vaultId,
                invitee.getUserId(),
                inviteId,
                currentUserId,
                now
        );

        auditService.appendInviteCreated(
                currentUserId,
                vaultId,
                inviteId,
                invitee.getUserId(),
                invitee.getEmail(),
                input.role(),
                now
        );

        return new CreateVaultInviteResponse(
                inviteId,
                invitee.getUserId(),
                invitee.getEmail(),
                VaultInviteStatus.PENDING,
                expiresAt,
                now
        );
    }

    private void validateInviteCreationAccess(UUID vaultId, UUID currentUserId, OffsetDateTime now) {
        if (!vaultRepository.existsById(vaultId)) {
            throw new ResourceNotFoundException("Vault not found");
        }

        vaultAccessService.requireOwnerMembership(vaultId, currentUserId, now);
    }

    private Vault loadVaultOrThrow(UUID vaultId) {
        return vaultRepository.findById(vaultId)
                .orElseThrow(() -> new ResourceNotFoundException("Vault not found"));
    }

    private User loadInviteeOrThrow(String inviteeEmail) {
        return userRepository.findByEmailIgnoreCaseAndStatus(inviteeEmail, UserStatus.ACTIVE)
                .orElseThrow(() -> new ResourceNotFoundException("Invitee user not found"));
    }

    private void validateInvitee(
            UUID vaultId,
            CreateVaultInviteInput input,
            UUID currentUserId,
            User invitee
    ) {
        if (input.role() == VaultMemberRole.OWNER) {
            throw new ConflictException("Cannot invite user with OWNER role");
        }

        if (invitee.getUserId().equals(currentUserId)) {
            throw new ConflictException("Cannot invite yourself to vault");
        }

        validateMembershipForInvite(vaultId, invitee.getUserId());
    }

    private UserKeyMaterial loadInviteeKeyMaterialOrThrow(UUID inviteeUserId) {
        return userKeyMaterialRepository.findById(inviteeUserId)
                .orElseThrow(() -> new ResourceNotFoundException("Invitee key material not found"));
    }

    private void validateMembershipForInvite(UUID vaultId, UUID inviteeUserId) {
        VaultMemberId memberId = new VaultMemberId(vaultId, inviteeUserId);

        VaultMember existingMembership = vaultMemberRepository.findById(memberId).orElse(null);
        if (existingMembership == null) {
            return;
        }

        if (existingMembership.getStatus() == VaultMemberStatus.ACTIVE) {
            throw new ConflictException("User is already an active member of this vault");
        }

        if (existingMembership.getStatus() == VaultMemberStatus.INVITED
                && existingMembership.getRevokedAt() == null) {
            throw new ConflictException("User is already invited to this vault");
        }
    }

    private VaultMember prepareMembershipForInvite(
            UUID vaultId,
            UUID inviteeUserId,
            VaultMemberRole role,
            OffsetDateTime now
    ) {
        VaultMemberId memberId = new VaultMemberId(vaultId, inviteeUserId);
        VaultMember existingMembership = vaultMemberRepository.findById(memberId).orElse(null);

        if (existingMembership == null) {
            return VaultMember.builder()
                    .id(memberId)
                    .role(role)
                    .status(VaultMemberStatus.INVITED)
                    .joinedAt(now)
                    .expiresAt(null)
                    .revokedAt(null)
                    .build();
        }

        existingMembership.setRole(role);
        existingMembership.setStatus(VaultMemberStatus.INVITED);
        existingMembership.setJoinedAt(now);
        existingMembership.setExpiresAt(null);
        existingMembership.setRevokedAt(null);

        return existingMembership;
    }

    private VaultInvite buildInvite(
            UUID inviteId,
            UUID vaultId,
            UUID currentUserId,
            User invitee,
            VaultMemberRole role,
            OffsetDateTime now,
            OffsetDateTime expiresAt
    ) {
        return VaultInvite.builder()
                .inviteId(inviteId)
                .vaultId(vaultId)
                .createdByUserId(currentUserId)
                .inviteeUserId(invitee.getUserId())
                .inviteeEmail(invitee.getEmail())
                .role(role)
                .status(VaultInviteStatus.PENDING)
                .createdAt(now)
                .expiresAt(expiresAt)
                .acceptedAt(null)
                .revokedAt(null)
                .build();
    }

    private VaultKeyEnvelope buildInviteEnvelope(
            UUID vaultId,
            UUID currentUserId,
            UUID inviteeUserId,
            int recipientEncryptionKeyVersion,
            int vaultKeyVersion,
            CreateVaultInviteInput input,
            OffsetDateTime now
    ) {
        return VaultKeyEnvelope.builder()
                .envelopeId(UUID.randomUUID())
                .vaultId(vaultId)
                .recipientUserId(inviteeUserId)
                .recipientEncryptionKeyVersion(recipientEncryptionKeyVersion)
                .vaultKeyVersion(vaultKeyVersion)
                .envelopeVersion(CURRENT_ENVELOPE_VERSION)
                .encryptedVaultKey(input.encryptedVaultKey())
                .envelopeParams(input.envelopeParams())
                .createdByUserId(currentUserId)
                .createdAt(now)
                .revokedAt(null)
                .build();
    }

    @Transactional
    public void acceptInvite(UUID inviteId, UUID currentUserId) {
        OffsetDateTime now = OffsetDateTime.now();

        VaultInvite invite = getIncomingInviteOrThrow(inviteId, currentUserId);
        validateAcceptableInvite(invite, now);

        VaultMember membership = getInviteMembershipOrThrow(invite.getVaultId(), currentUserId);
        validateAcceptableMembership(membership);

        markInviteAccepted(invite, now);
        activateMembership(membership);

        vaultMemberRepository.save(membership);
        vaultInviteRepository.save(invite);

        vaultSyncService.appendTargetedMembershipChanged(
                invite.getVaultId(),
                currentUserId,
                invite.getInviteId(),
                currentUserId,
                now
        );

        auditService.appendInviteAccepted(currentUserId, invite.getVaultId(), invite.getInviteId(), now);
    }

    private void validateAcceptableInvite(VaultInvite invite, OffsetDateTime now) {
        if (invite.getRevokedAt() != null || invite.getStatus() == VaultInviteStatus.REVOKED) {
            throw new ConflictException("Vault invite has been revoked");
        }

        if (invite.getAcceptedAt() != null || invite.getStatus() == VaultInviteStatus.ACCEPTED) {
            throw new ConflictException("Vault invite is already accepted");
        }

        if (invite.getStatus() == VaultInviteStatus.DECLINED) {
            throw new ConflictException("Declined invite cannot be accepted");
        }

        if (invite.getStatus() == VaultInviteStatus.EXPIRED) {
            throw new ConflictException("Vault invite has expired");
        }

        if (invite.getExpiresAt() != null && !invite.getExpiresAt().isAfter(now)) {
            invite.setStatus(VaultInviteStatus.EXPIRED);
            vaultInviteRepository.save(invite);
            throw new ConflictException("Vault invite has expired");
        }
    }

    private void validateAcceptableMembership(VaultMember membership) {
        if (membership.getStatus() != VaultMemberStatus.INVITED) {
            throw new ConflictException("Vault membership is not in INVITED status");
        }

        if (membership.getRevokedAt() != null) {
            throw new ConflictException("Vault membership has been revoked");
        }
    }

    private void markInviteAccepted(VaultInvite invite, OffsetDateTime now) {
        invite.setStatus(VaultInviteStatus.ACCEPTED);
        invite.setAcceptedAt(now);
    }

    private void activateMembership(VaultMember membership) {
        membership.setStatus(VaultMemberStatus.ACTIVE);
    }

    @Transactional
    public void revokeInvite(UUID vaultId, UUID inviteId, UUID currentUserId) {
        OffsetDateTime now = OffsetDateTime.now();

        validateOwnerAccess(vaultId, currentUserId, now);

        VaultInvite invite = getVaultInviteOrThrow(vaultId, inviteId);
        validateRevocableInvite(invite);

        VaultMember membership = getInviteMembershipOrThrow(vaultId, invite.getInviteeUserId());
        revokePendingInvite(invite, now);
        revokeInvitedMembershipIfNeeded(membership, now);

        vaultInviteRepository.save(invite);
        vaultMemberRepository.save(membership);

        revokeActiveEnvelopes(vaultId, invite.getInviteeUserId(), now);
        vaultSyncService.appendTargetedMembershipChanged(
                vaultId,
                invite.getInviteeUserId(),
                invite.getInviteId(),
                currentUserId,
                now
        );

        auditService.appendInviteRevoked(currentUserId, vaultId, invite.getInviteId(), invite.getInviteeUserId(), now);
    }

    private void validateOwnerAccess(UUID vaultId, UUID currentUserId, OffsetDateTime now) {
        if (!vaultRepository.existsById(vaultId)) {
            throw new ResourceNotFoundException("Vault not found");
        }

        vaultAccessService.requireOwnerMembership(vaultId, currentUserId, now);
    }

    private VaultInvite getVaultInviteOrThrow(UUID vaultId, UUID inviteId) {
        return vaultInviteRepository.findByInviteIdAndVaultId(inviteId, vaultId)
                .orElseThrow(() -> new ResourceNotFoundException("Vault invite not found"));
    }

    private void validateRevocableInvite(VaultInvite invite) {
        if (invite.getRevokedAt() != null || invite.getStatus() == VaultInviteStatus.REVOKED) {
            throw new ConflictException("Vault invite is already revoked");
        }

        if (invite.getAcceptedAt() != null || invite.getStatus() == VaultInviteStatus.ACCEPTED) {
            throw new ConflictException("Accepted invite cannot be revoked as pending invite");
        }

        if (invite.getStatus() == VaultInviteStatus.DECLINED) {
            throw new ConflictException("Declined invite cannot be revoked as pending invite");
        }

        if (invite.getStatus() == VaultInviteStatus.EXPIRED) {
            throw new ConflictException("Expired invite cannot be revoked as pending invite");
        }
    }

    private void revokePendingInvite(VaultInvite invite, OffsetDateTime now) {
        invite.setStatus(VaultInviteStatus.REVOKED);
        invite.setRevokedAt(now);
    }

    private void revokeInvitedMembershipIfNeeded(VaultMember membership, OffsetDateTime now) {
        if (membership.getStatus() == VaultMemberStatus.INVITED) {
            membership.setStatus(VaultMemberStatus.REVOKED);
            membership.setRevokedAt(now);
        }
    }

    @Transactional
    public void changeMemberRole(
            UUID vaultId,
            UUID targetUserId,
            ChangeVaultMemberRoleInput input,
            UUID currentUserId
    ) {
        OffsetDateTime now = OffsetDateTime.now();

        validateOwnerAccess(vaultId, currentUserId, now);
        validateRoleChangeRequest(targetUserId, input, currentUserId);

        VaultMember membership = getVaultMemberOrThrow(vaultId, targetUserId);
        validateRoleChangeableMembership(membership);

        applyRoleChange(membership, input.role());

        vaultMemberRepository.save(membership);
        vaultSyncService.appendTargetedMembershipChanged(
                vaultId,
                targetUserId,
                null,
                currentUserId,
                now
        );

        auditService.appendMemberRoleChanged(currentUserId, vaultId, targetUserId, input.role(), now);
    }

    @Transactional
    public void transferOwnership(
            UUID vaultId,
            UUID targetUserId,
            UUID currentUserId
    ) {
        OffsetDateTime now = OffsetDateTime.now();

        validateOwnerAccess(vaultId, currentUserId, now);
        validateOwnershipTransferRequest(targetUserId, currentUserId);

        VaultMember currentOwnerMembership = getVaultMemberOrThrow(vaultId, currentUserId);
        VaultMember targetMembership = getVaultMemberOrThrow(vaultId, targetUserId);

        validateCurrentOwnerMembership(currentOwnerMembership);
        validateOwnershipTransferTarget(targetMembership);

        currentOwnerMembership.setRole(VaultMemberRole.EDITOR);
        targetMembership.setRole(VaultMemberRole.OWNER);

        vaultMemberRepository.saveAll(List.of(currentOwnerMembership, targetMembership));

        vaultSyncService.appendTargetedMembershipChanged(
                vaultId,
                currentUserId,
                null,
                currentUserId,
                now
        );
        vaultSyncService.appendTargetedMembershipChanged(
                vaultId,
                targetUserId,
                null,
                currentUserId,
                now
        );

        auditService.appendOwnershipTransferred(currentUserId, vaultId, targetUserId, now);
    }

    private void validateRoleChangeRequest(
            UUID targetUserId,
            ChangeVaultMemberRoleInput input,
            UUID currentUserId
    ) {
        if (targetUserId.equals(currentUserId)) {
            throw new ConflictException("Cannot change your own role without ownership transfer flow");
        }

        if (input.role() == VaultMemberRole.OWNER) {
            throw new ConflictException("Cannot assign OWNER role through role change endpoint");
        }
    }

    private void validateOwnershipTransferRequest(UUID targetUserId, UUID currentUserId) {
        if (targetUserId.equals(currentUserId)) {
            throw new ConflictException("Cannot transfer ownership to yourself");
        }
    }

    private VaultMember getVaultMemberOrThrow(UUID vaultId, UUID targetUserId) {
        return vaultMemberRepository.findById(new VaultMemberId(vaultId, targetUserId))
                .orElseThrow(() -> new ResourceNotFoundException("Vault member not found"));
    }

    private void validateCurrentOwnerMembership(VaultMember membership) {
        if (membership.getRole() != VaultMemberRole.OWNER) {
            throw new ConflictException("Only current vault owner can transfer ownership");
        }

        if (membership.getStatus() != VaultMemberStatus.ACTIVE || membership.getRevokedAt() != null) {
            throw new ConflictException("Only active owner can transfer vault ownership");
        }
    }

    private void validateRoleChangeableMembership(VaultMember membership) {
        if (membership.getRole() == VaultMemberRole.OWNER) {
            throw new ConflictException("Cannot change role of vault owner");
        }

        if (membership.getStatus() != VaultMemberStatus.ACTIVE) {
            throw new ConflictException("Role can only be changed for ACTIVE member");
        }

        if (membership.getRevokedAt() != null) {
            throw new ConflictException("Vault member has been revoked");
        }
    }

    private void validateOwnershipTransferTarget(VaultMember membership) {
        if (membership.getRole() == VaultMemberRole.OWNER) {
            throw new ConflictException("Selected member already owns this vault");
        }

        if (membership.getStatus() != VaultMemberStatus.ACTIVE) {
            throw new ConflictException("Ownership can only be transferred to ACTIVE member");
        }

        if (membership.getRevokedAt() != null) {
            throw new ConflictException("Ownership cannot be transferred to revoked member");
        }
    }

    private void applyRoleChange(VaultMember membership, VaultMemberRole newRole) {
        membership.setRole(newRole);
    }

    @Transactional
    public void revokeMember(UUID vaultId, UUID targetUserId, UUID currentUserId) {
        OffsetDateTime now = OffsetDateTime.now();

        validateOwnerAccess(vaultId, currentUserId, now);
        validateMemberRevokeRequest(targetUserId, currentUserId);

        VaultMember membership = getVaultMemberOrThrow(vaultId, targetUserId);
        validateRevocableMembership(membership);

        revokeActiveMembership(membership, now);

        vaultMemberRepository.save(membership);
        revokeActiveEnvelopes(vaultId, targetUserId, now);
        vaultSyncService.appendTargetedMembershipChanged(
                vaultId,
                targetUserId,
                null,
                currentUserId,
                now
        );

        auditService.appendMemberRevoked(currentUserId, vaultId, targetUserId, now);
    }

    private void validateMemberRevokeRequest(UUID targetUserId, UUID currentUserId) {
        if (targetUserId.equals(currentUserId)) {
            throw new ConflictException("Cannot revoke yourself without ownership transfer flow");
        }
    }

    private void validateRevocableMembership(VaultMember membership) {
        if (membership.getRole() == VaultMemberRole.OWNER) {
            throw new ConflictException("Cannot revoke vault owner");
        }

        if (membership.getStatus() == VaultMemberStatus.REVOKED || membership.getRevokedAt() != null) {
            throw new ConflictException("Vault member is already revoked");
        }

        if (membership.getStatus() == VaultMemberStatus.INVITED) {
            throw new ConflictException("Use invite revoke flow for INVITED membership");
        }
    }

    private void revokeActiveMembership(VaultMember membership, OffsetDateTime now) {
        membership.setStatus(VaultMemberStatus.REVOKED);
        membership.setRevokedAt(now);
    }

    @Transactional
    public void declineInvite(UUID inviteId, UUID currentUserId) {
        OffsetDateTime now = OffsetDateTime.now();

        VaultInvite invite = getIncomingInviteOrThrow(inviteId, currentUserId);
        validateDeclinableInvite(invite, now);

        VaultMember membership = getInviteMembershipOrThrow(invite.getVaultId(), currentUserId);
        validateDeclinableMembership(membership);

        markInviteDeclined(invite, now);
        revokeInvitedMembership(membership, now);

        vaultInviteRepository.save(invite);
        vaultMemberRepository.save(membership);

        revokeActiveEnvelopes(invite.getVaultId(), currentUserId, now);
        vaultSyncService.appendTargetedMembershipChanged(
                invite.getVaultId(),
                currentUserId,
                invite.getInviteId(),
                currentUserId,
                now
        );

        auditService.appendInviteDeclined(currentUserId, invite.getVaultId(), invite.getInviteId(), now);
    }

    private VaultInvite getIncomingInviteOrThrow(UUID inviteId, UUID currentUserId) {
        return vaultInviteRepository.findByInviteIdAndInviteeUserId(inviteId, currentUserId)
                .orElseThrow(() -> new ResourceNotFoundException("Vault invite not found"));
    }

    private void validateDeclinableInvite(VaultInvite invite, OffsetDateTime now) {
        if (invite.getStatus() == VaultInviteStatus.ACCEPTED || invite.getAcceptedAt() != null) {
            throw new ConflictException("Accepted invite cannot be declined");
        }

        if (invite.getStatus() == VaultInviteStatus.REVOKED || invite.getRevokedAt() != null) {
            throw new ConflictException("Vault invite has been revoked");
        }

        if (invite.getStatus() == VaultInviteStatus.DECLINED) {
            throw new ConflictException("Vault invite is already declined");
        }

        if (invite.getStatus() == VaultInviteStatus.EXPIRED) {
            throw new ConflictException("Vault invite has expired");
        }

        if (invite.getExpiresAt() != null && !invite.getExpiresAt().isAfter(now)) {
            invite.setStatus(VaultInviteStatus.EXPIRED);
            vaultInviteRepository.save(invite);
            throw new ConflictException("Vault invite has expired");
        }
    }

    private VaultMember getInviteMembershipOrThrow(UUID vaultId, UUID currentUserId) {
        return vaultMemberRepository.findById(new VaultMemberId(vaultId, currentUserId))
                .orElseThrow(() -> new ResourceNotFoundException("Vault membership not found for invite"));
    }

    private void validateDeclinableMembership(VaultMember membership) {
        if (membership.getStatus() != VaultMemberStatus.INVITED) {
            throw new ConflictException("Vault membership is not in INVITED status");
        }
    }

    private void markInviteDeclined(VaultInvite invite, OffsetDateTime now) {
        invite.setStatus(VaultInviteStatus.DECLINED);
        invite.setRevokedAt(now);
    }

    private void revokeInvitedMembership(VaultMember membership, OffsetDateTime now) {
        membership.setStatus(VaultMemberStatus.REVOKED);
        membership.setRevokedAt(now);
    }

    private void revokeActiveEnvelopes(UUID vaultId, UUID recipientUserId, OffsetDateTime now) {
        List<VaultKeyEnvelope> envelopes = vaultKeyEnvelopeRepository.findActiveEnvelopes(
                vaultId,
                recipientUserId
        );

        for (VaultKeyEnvelope envelope : envelopes) {
            envelope.setRevokedAt(now);
        }

        vaultKeyEnvelopeRepository.saveAll(envelopes);
    }
}
