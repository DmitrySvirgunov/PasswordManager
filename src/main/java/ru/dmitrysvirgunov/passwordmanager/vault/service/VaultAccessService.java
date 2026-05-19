package ru.dmitrysvirgunov.passwordmanager.vault.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.dmitrysvirgunov.passwordmanager.common.exception.ApplicationAccessDeniedException;
import ru.dmitrysvirgunov.passwordmanager.vault.entity.VaultMember;
import ru.dmitrysvirgunov.passwordmanager.vault.entity.VaultMemberId;
import ru.dmitrysvirgunov.passwordmanager.vault.model.VaultMemberRole;
import ru.dmitrysvirgunov.passwordmanager.vault.model.VaultMemberStatus;
import ru.dmitrysvirgunov.passwordmanager.vault.repository.VaultMemberRepository;

import java.time.OffsetDateTime;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class VaultAccessService {

    private final VaultMemberRepository vaultMemberRepository;

    @Transactional(readOnly = true)
    public VaultMember requireReadableMembership(UUID vaultId, UUID userId, OffsetDateTime now) {
        VaultMember membership = vaultMemberRepository.findById(new VaultMemberId(vaultId, userId))
                .orElseThrow(() -> new ApplicationAccessDeniedException("Access to vault denied"));

        validateReadable(membership, now);
        return membership;
    }

    @Transactional(readOnly = true)
    public VaultMember requireWritableMembership(UUID vaultId, UUID userId, OffsetDateTime now) {
        VaultMember membership = vaultMemberRepository.findById(new VaultMemberId(vaultId, userId))
                .orElseThrow(() -> new ApplicationAccessDeniedException("Access to vault denied"));

        validateWritable(membership, now);
        return membership;
    }

    private void validateReadable(VaultMember membership, OffsetDateTime now) {
        if (membership.getStatus() != VaultMemberStatus.ACTIVE) {
            throw new ApplicationAccessDeniedException("Vault membership is not active");
        }

        if (membership.getRevokedAt() != null) {
            throw new ApplicationAccessDeniedException("Vault membership has been revoked");
        }

        if (membership.getExpiresAt() != null && !membership.getExpiresAt().isAfter(now)) {
            throw new ApplicationAccessDeniedException("Vault membership has expired");
        }
    }

    private void validateWritable(VaultMember membership, OffsetDateTime now) {
        validateReadable(membership, now);

        if (membership.getRole() == VaultMemberRole.READER) {
            throw new ApplicationAccessDeniedException("Write access to vault denied");
        }
    }

    @Transactional(readOnly = true)
    public VaultMember requireOwnerMembership(UUID vaultId, UUID userId, OffsetDateTime now) {
        VaultMember membership = requireWritableMembership(vaultId, userId, now);

        if (membership.getRole() != VaultMemberRole.OWNER) {
            throw new ApplicationAccessDeniedException("Owner access to vault required");
        }

        return membership;
    }
}