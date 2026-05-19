package ru.dmitrysvirgunov.passwordmanager.vault.service;

import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.dmitrysvirgunov.passwordmanager.auth.entity.User;
import ru.dmitrysvirgunov.passwordmanager.auth.entity.UserKeyMaterial;
import ru.dmitrysvirgunov.passwordmanager.auth.model.UserStatus;
import ru.dmitrysvirgunov.passwordmanager.auth.repository.UserKeyMaterialRepository;
import ru.dmitrysvirgunov.passwordmanager.auth.repository.UserRepository;
import ru.dmitrysvirgunov.passwordmanager.common.exception.ConflictException;
import ru.dmitrysvirgunov.passwordmanager.common.exception.ResourceNotFoundException;
import ru.dmitrysvirgunov.passwordmanager.vault.dto.response.membership.IncomingVaultInviteResponse;
import ru.dmitrysvirgunov.passwordmanager.vault.dto.response.membership.VaultInviteeKeyMaterialResponse;
import ru.dmitrysvirgunov.passwordmanager.vault.dto.response.list.ListIncomingVaultInvitesResponse;
import ru.dmitrysvirgunov.passwordmanager.vault.dto.response.list.ListVaultEnvelopesResponse;
import ru.dmitrysvirgunov.passwordmanager.vault.dto.response.list.ListVaultInvitesResponse;
import ru.dmitrysvirgunov.passwordmanager.vault.dto.response.list.ListVaultMembersResponse;
import ru.dmitrysvirgunov.passwordmanager.vault.dto.response.list.ListVaultObjectRevisionsResponse;
import ru.dmitrysvirgunov.passwordmanager.vault.dto.response.list.ListVaultObjectsResponse;
import ru.dmitrysvirgunov.passwordmanager.vault.dto.response.list.ListVaultsResponse;
import ru.dmitrysvirgunov.passwordmanager.vault.dto.response.vault.VaultDetailsResponse;
import ru.dmitrysvirgunov.passwordmanager.vault.dto.response.vault.VaultEnvelopeResponse;
import ru.dmitrysvirgunov.passwordmanager.vault.dto.response.membership.VaultInviteResponse;
import ru.dmitrysvirgunov.passwordmanager.vault.dto.response.membership.VaultMemberResponse;
import ru.dmitrysvirgunov.passwordmanager.vault.dto.response.object.VaultObjectRevisionResponse;
import ru.dmitrysvirgunov.passwordmanager.vault.dto.response.object.VaultObjectSnapshotResponse;
import ru.dmitrysvirgunov.passwordmanager.vault.dto.response.vault.VaultSummaryResponse;
import ru.dmitrysvirgunov.passwordmanager.vault.entity.Vault;
import ru.dmitrysvirgunov.passwordmanager.vault.entity.VaultInvite;
import ru.dmitrysvirgunov.passwordmanager.vault.entity.VaultKeyEnvelope;
import ru.dmitrysvirgunov.passwordmanager.vault.entity.VaultMember;
import ru.dmitrysvirgunov.passwordmanager.vault.entity.VaultObject;
import ru.dmitrysvirgunov.passwordmanager.vault.entity.VaultObjectRevision;
import ru.dmitrysvirgunov.passwordmanager.vault.entity.VaultObjectRevisionBlob;
import ru.dmitrysvirgunov.passwordmanager.vault.mapper.VaultObjectResponseMapper;
import ru.dmitrysvirgunov.passwordmanager.vault.mapper.VaultResponseMapper;
import ru.dmitrysvirgunov.passwordmanager.vault.model.BlobReferenceInput;
import ru.dmitrysvirgunov.passwordmanager.vault.model.VaultMemberRole;
import ru.dmitrysvirgunov.passwordmanager.vault.model.VaultMemberStatus;
import ru.dmitrysvirgunov.passwordmanager.vault.repository.VaultInviteRepository;
import ru.dmitrysvirgunov.passwordmanager.vault.repository.VaultKeyEnvelopeRepository;
import ru.dmitrysvirgunov.passwordmanager.vault.repository.VaultMemberRepository;
import ru.dmitrysvirgunov.passwordmanager.vault.repository.VaultObjectRepository;
import ru.dmitrysvirgunov.passwordmanager.vault.repository.VaultObjectRevisionBlobRepository;
import ru.dmitrysvirgunov.passwordmanager.vault.repository.VaultObjectRevisionRepository;
import ru.dmitrysvirgunov.passwordmanager.vault.repository.VaultRepository;
import ru.dmitrysvirgunov.passwordmanager.vault.dto.response.list.ListVaultSharingMaterialsResponse;
import ru.dmitrysvirgunov.passwordmanager.vault.dto.response.vault.VaultSharingMaterialResponse;

import java.util.*;
import java.time.OffsetDateTime;
import java.util.function.Function;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class VaultQueryService {

    private final VaultRepository vaultRepository;
    private final VaultMemberRepository vaultMemberRepository;
    private final VaultInviteRepository vaultInviteRepository;
    private final VaultKeyEnvelopeRepository vaultKeyEnvelopeRepository;
    private final VaultObjectRepository vaultObjectRepository;
    private final VaultObjectRevisionRepository vaultObjectRevisionRepository;
    private final VaultObjectRevisionBlobRepository vaultObjectRevisionBlobRepository;
    private final UserRepository userRepository;
    private final UserKeyMaterialRepository userKeyMaterialRepository;
    private final VaultAccessService vaultAccessService;
    private final VaultSharingAntiAbuseService vaultSharingAntiAbuseService;
    private final VaultResponseMapper vaultResponseMapper;
    private final VaultObjectResponseMapper vaultObjectResponseMapper;
    private final VaultObjectSignatureVerificationService vaultObjectSignatureVerificationService;

    @Transactional(readOnly = true)
    public ListVaultsResponse getVaults(
            int page,
            int size,
            Jwt jwt
    ) {
        UUID currentUserId = UUID.fromString(jwt.getSubject());
        OffsetDateTime now = OffsetDateTime.now();

        Page<VaultMember> membershipsPage = vaultMemberRepository.findReadableMemberships(
                currentUserId,
                VaultMemberStatus.ACTIVE,
                now,
                PageRequest.of(page - 1, size)
        );

        if (membershipsPage.getTotalPages() > 0 && page > membershipsPage.getTotalPages()) {
            membershipsPage = vaultMemberRepository.findReadableMemberships(
                    currentUserId,
                    VaultMemberStatus.ACTIVE,
                    now,
                    PageRequest.of(membershipsPage.getTotalPages() - 1, size)
            );
        }

        List<VaultMember> memberships = membershipsPage.getContent();
        long totalItems = membershipsPage.getTotalElements();
        int totalPages = membershipsPage.getTotalPages();
        int currentPage = membershipsPage.getNumber() + 1;
        long ownedCount = vaultMemberRepository.countReadableMembershipsByRole(
                currentUserId,
                VaultMemberStatus.ACTIVE,
                VaultMemberRole.OWNER,
                now
        );
        long sharedCount = Math.max(0, totalItems - ownedCount);

        List<UUID> vaultIds = memberships.stream()
                .map(membership -> membership.getId().getVaultId())
                .toList();

        if (vaultIds.isEmpty()) {
            return new ListVaultsResponse(
                    List.of(),
                    currentPage,
                    size,
                    totalItems,
                    totalPages,
                    ownedCount,
                    sharedCount
            );
        }

        Map<UUID, Vault> vaultsById = vaultRepository.findAllById(vaultIds).stream()
                .collect(Collectors.toMap(
                        Vault::getVaultId,
                        Function.identity()
                ));

        UserKeyMaterial userKeyMaterial = loadUserKeyMaterialOrThrow(currentUserId);

        Map<UUID, VaultKeyEnvelope> envelopesByVaultId = vaultKeyEnvelopeRepository
                .findCurrentActiveEnvelopesForRecipientAndVaultIds(
                        currentUserId,
                        userKeyMaterial.getEncryptionKeyVersion(),
                        vaultIds
                )
                .stream()
                .collect(Collectors.toMap(
                        VaultKeyEnvelope::getVaultId,
                        Function.identity()
                ));

        List<VaultSummaryResponse> items = memberships.stream()
                .map(membership -> toVaultSummaryResponse(
                        membership,
                        vaultsById,
                        envelopesByVaultId,
                        userKeyMaterial.getEncryptionKeyVersion()
                ))
                .toList();

        return new ListVaultsResponse(
                items,
                currentPage,
                size,
                totalItems,
                totalPages,
                ownedCount,
                sharedCount
        );
    }

    @Transactional(readOnly = true)
    public VaultDetailsResponse getVault(UUID vaultId, Jwt jwt) {
        UUID currentUserId = UUID.fromString(jwt.getSubject());
        OffsetDateTime now = OffsetDateTime.now();

        VaultMember membership = vaultAccessService.requireReadableMembership(vaultId, currentUserId, now);
        Vault vault = loadVaultOrThrow(vaultId);
        UserKeyMaterial userKeyMaterial = loadUserKeyMaterialOrThrow(currentUserId);

        VaultKeyEnvelope envelope = vaultKeyEnvelopeRepository
                .findActiveEnvelope(
                        vaultId,
                        currentUserId,
                        vault.getCurrentVaultKeyVersion(),
                        userKeyMaterial.getEncryptionKeyVersion()
                )
                .orElseThrow(() -> new ConflictException(
                        "Active vault envelope not found for current vault key version and current user's encryption key version"
                ));

        return vaultResponseMapper.toDetailsResponse(vault, membership, envelope);
    }

    @Transactional(readOnly = true)
    public ListVaultEnvelopesResponse getVaultEnvelopes(UUID vaultId, Jwt jwt) {
        UUID currentUserId = UUID.fromString(jwt.getSubject());
        OffsetDateTime now = OffsetDateTime.now();

        vaultAccessService.requireReadableMembership(vaultId, currentUserId, now);
        Vault vault = loadVaultOrThrow(vaultId);

        List<VaultKeyEnvelope> envelopes =
                vaultKeyEnvelopeRepository.findActiveEnvelopesForRecipient(
                        vaultId,
                        currentUserId
                );

        List<VaultEnvelopeResponse> items = envelopes.stream()
                .map(vaultResponseMapper::toEnvelopeResponse)
                .toList();

        return new ListVaultEnvelopesResponse(
                vaultId,
                vault.getCurrentVaultKeyVersion(),
                items
        );
    }

    @Transactional(readOnly = true)
    public ListVaultObjectsResponse getVaultObjects(
            UUID vaultId,
            boolean includeDeleted,
            int page,
            int size,
            Jwt jwt
    ) {
        UUID currentUserId = UUID.fromString(jwt.getSubject());
        OffsetDateTime now = OffsetDateTime.now();

        vaultAccessService.requireReadableMembership(vaultId, currentUserId, now);

        Page<VaultObject> objectsPage = includeDeleted
                ? vaultObjectRepository.findByVaultIdOrderByUpdatedAtDescObjectIdDesc(
                        vaultId,
                        PageRequest.of(page - 1, size)
                )
                : vaultObjectRepository.findByVaultIdAndDeletedFalseOrderByUpdatedAtDescObjectIdDesc(
                        vaultId,
                        PageRequest.of(page - 1, size)
                );

        if (objectsPage.getTotalPages() > 0 && page > objectsPage.getTotalPages()) {
            objectsPage = includeDeleted
                    ? vaultObjectRepository.findByVaultIdOrderByUpdatedAtDescObjectIdDesc(
                            vaultId,
                            PageRequest.of(objectsPage.getTotalPages() - 1, size)
                    )
                    : vaultObjectRepository.findByVaultIdAndDeletedFalseOrderByUpdatedAtDescObjectIdDesc(
                            vaultId,
                            PageRequest.of(objectsPage.getTotalPages() - 1, size)
                    );
        }

        List<VaultObject> objects = objectsPage.getContent();

        List<VaultObjectSnapshotResponse> items = objects.stream()
                .map(this::loadCurrentSnapshot)
                .toList();

        return new ListVaultObjectsResponse(
                items,
                objectsPage.getNumber() + 1,
                size,
                objectsPage.getTotalElements(),
                objectsPage.getTotalPages()
        );
    }

    @Transactional(readOnly = true)
    public VaultObjectSnapshotResponse getVaultObject(
            UUID vaultId,
            UUID objectId,
            boolean includeDeleted,
            Jwt jwt
    ) {
        UUID currentUserId = UUID.fromString(jwt.getSubject());
        OffsetDateTime now = OffsetDateTime.now();

        vaultAccessService.requireReadableMembership(vaultId, currentUserId, now);

        VaultObject object = vaultObjectRepository.findByObjectIdAndVaultId(objectId, vaultId)
                .orElseThrow(() -> new ResourceNotFoundException("Vault object not found"));

        if (object.isDeleted() && !includeDeleted) {
            throw new ResourceNotFoundException("Vault object not found");
        }

        return loadCurrentSnapshot(object);
    }

    @Transactional(readOnly = true)
    public ListVaultObjectRevisionsResponse getVaultObjectRevisions(
            UUID vaultId,
            UUID objectId,
            Jwt jwt
    ) {
        UUID currentUserId = UUID.fromString(jwt.getSubject());
        OffsetDateTime now = OffsetDateTime.now();

        vaultAccessService.requireReadableMembership(vaultId, currentUserId, now);

        VaultObject object = vaultObjectRepository.findByObjectIdAndVaultId(objectId, vaultId)
                .orElseThrow(() -> new ResourceNotFoundException("Vault object not found"));

        List<VaultObjectRevision> revisionEntities = vaultObjectRevisionRepository.findByObjectIdOrderByVersionDesc(objectId);
        Map<UUID, String> signerEmailsByUserId = loadUserEmailsByIds(
                revisionEntities.stream()
                        .map(VaultObjectRevision::getSignedByUserId)
                        .filter(Objects::nonNull)
                        .distinct()
                        .toList()
        );

        List<VaultObjectRevisionResponse> revisions = revisionEntities
                .stream()
                .map(revision -> {
                    List<VaultObjectRevisionBlob> blobReferences = loadBlobReferences(revision.getRevisionId());
                    return vaultObjectResponseMapper.toRevisionResponse(
                            revision,
                            blobReferences,
                            vaultObjectSignatureVerificationService.verifyRevision(
                                    revision,
                                    toBlobReferenceInputs(blobReferences)
                            ),
                            signerEmailsByUserId.get(revision.getSignedByUserId())
                    );
                })
                .toList();

        return new ListVaultObjectRevisionsResponse(
                object.getObjectId(),
                object.getCurrentVersion(),
                object.isDeleted(),
                revisions
        );
    }

    @Transactional(readOnly = true)
    public VaultObjectRevisionResponse getVaultObjectRevision(
            UUID vaultId,
            UUID objectId,
            int version,
            Jwt jwt
    ) {
        UUID currentUserId = UUID.fromString(jwt.getSubject());
        OffsetDateTime now = OffsetDateTime.now();

        vaultAccessService.requireReadableMembership(vaultId, currentUserId, now);

        VaultObject object = vaultObjectRepository.findByObjectIdAndVaultId(objectId, vaultId)
                .orElseThrow(() -> new ResourceNotFoundException("Vault object not found"));

        VaultObjectRevision revision = vaultObjectRevisionRepository.findByObjectIdAndVersion(object.getObjectId(), version)
                .orElseThrow(() -> new ResourceNotFoundException("Vault object revision not found"));
        List<VaultObjectRevisionBlob> blobReferences = loadBlobReferences(revision.getRevisionId());

        return vaultObjectResponseMapper.toRevisionResponse(
                revision,
                blobReferences,
                vaultObjectSignatureVerificationService.verifyRevision(
                        revision,
                        toBlobReferenceInputs(blobReferences)
                ),
                loadUserEmail(revision.getSignedByUserId())
        );
    }

    @Transactional(readOnly = true)
    public ListVaultMembersResponse getVaultMembers(UUID vaultId, Jwt jwt) {
        UUID currentUserId = UUID.fromString(jwt.getSubject());
        OffsetDateTime now = OffsetDateTime.now();

        vaultAccessService.requireReadableMembership(vaultId, currentUserId, now);

        List<VaultMember> members = vaultMemberRepository.findByIdVaultIdOrderByJoinedAtAsc(vaultId);

        List<UUID> userIds = members.stream()
                .map(member -> member.getId().getUserId())
                .toList();

        Map<UUID, User> usersById = userRepository.findAllById(userIds).stream()
                .collect(Collectors.toMap(
                        User::getUserId,
                        Function.identity()
                ));

        List<VaultMemberResponse> items = members.stream()
                .map(member -> toVaultMemberResponse(member, usersById))
                .toList();

        return new ListVaultMembersResponse(vaultId, items);
    }

    @Transactional(readOnly = true)
    public ListVaultInvitesResponse getVaultInvites(UUID vaultId, Jwt jwt) {
        UUID currentUserId = UUID.fromString(jwt.getSubject());
        OffsetDateTime now = OffsetDateTime.now();

        vaultAccessService.requireReadableMembership(vaultId, currentUserId, now);

        List<VaultInviteResponse> items = vaultInviteRepository.findByVaultIdOrderByCreatedAtDesc(vaultId).stream()
                .map(invite -> new VaultInviteResponse(
                        invite.getInviteId(),
                        invite.getInviteeEmail(),
                        invite.getInviteeUserId(),
                        invite.getRole(),
                        invite.getStatus(),
                        invite.getExpiresAt(),
                        invite.getCreatedAt(),
                        invite.getAcceptedAt(),
                        invite.getRevokedAt()
                ))
                .toList();

        return new ListVaultInvitesResponse(vaultId, items);
    }

    @Transactional(readOnly = true)
    public VaultInviteeKeyMaterialResponse getVaultInviteeKeyMaterial(
            UUID vaultId,
            String email,
            Jwt jwt
    ) {
        UUID currentUserId = UUID.fromString(jwt.getSubject());
        OffsetDateTime now = OffsetDateTime.now();

        vaultAccessService.requireOwnerMembership(vaultId, currentUserId, now);
        vaultSharingAntiAbuseService.checkInviteeKeyLookupAllowed(currentUserId, vaultId, email);

        User invitee = userRepository.findByEmailIgnoreCaseAndStatus(normalizeEmail(email), UserStatus.ACTIVE)
                .orElseThrow(() -> new ResourceNotFoundException("Invitee user not found"));

        UserKeyMaterial keyMaterial = userKeyMaterialRepository.findById(invitee.getUserId())
                .orElseThrow(() -> new ResourceNotFoundException("Invitee key material not found"));

        var encryptionKeyParams = keyMaterial.getEncryptionKeyParams();

        return new VaultInviteeKeyMaterialResponse(
                invitee.getUserId(),
                invitee.getEmail(),
                Base64.getEncoder().encodeToString(keyMaterial.getPublicEncryptionKey()),
                keyMaterial.getEncryptionKeyVersion(),
                encryptionKeyParams.keyAlgorithm(),
                encryptionKeyParams.publicKeyEncoding()
        );
    }

    @Transactional(readOnly = true)
    public ListIncomingVaultInvitesResponse getIncomingInvites(Jwt jwt) {
        UUID currentUserId = UUID.fromString(jwt.getSubject());

        List<VaultInvite> invites = vaultInviteRepository.findByInviteeUserIdOrderByCreatedAtDesc(currentUserId);
        Map<UUID, User> creatorsById = loadCreatorsById(invites);
        List<IncomingVaultInviteResponse> items = mapIncomingInvites(invites, creatorsById);

        return new ListIncomingVaultInvitesResponse(items);
    }

    private VaultSummaryResponse toVaultSummaryResponse(
            VaultMember membership,
            Map<UUID, Vault> vaultsById,
            Map<UUID, VaultKeyEnvelope> envelopesByVaultId,
            int currentEncryptionKeyVersion
    ) {
        UUID vaultId = membership.getId().getVaultId();

        Vault vault = vaultsById.get(vaultId);
        if (vault == null) {
            throw new ResourceNotFoundException("Vault not found for membership " + vaultId);
        }

        VaultKeyEnvelope envelope = envelopesByVaultId.get(vaultId);
        if (envelope == null) {
            throw new ConflictException(
                    "Current active vault envelope not found for vault " + vaultId
                            + ", currentEncryptionKeyVersion " + currentEncryptionKeyVersion
            );
        }

        return vaultResponseMapper.toSummaryResponse(vault, membership, envelope);
    }

    private VaultObjectSnapshotResponse loadCurrentSnapshot(VaultObject object) {
        VaultObjectRevision revision = vaultObjectRevisionRepository
                .findByObjectIdAndVersion(object.getObjectId(), object.getCurrentVersion())
                .orElseThrow(() -> new ResourceNotFoundException(
                        "Current revision not found for object " + object.getObjectId()
                ));
        List<VaultObjectRevisionBlob> blobReferences = loadBlobReferences(revision.getRevisionId());

        return vaultObjectResponseMapper.toSnapshotResponse(
                object,
                revision,
                blobReferences,
                vaultObjectSignatureVerificationService.verifyRevision(
                        revision,
                        toBlobReferenceInputs(blobReferences)
                ),
                loadUserEmail(revision.getSignedByUserId())
        );
    }

    private List<VaultObjectRevisionBlob> loadBlobReferences(UUID revisionId) {
        return vaultObjectRevisionBlobRepository.findByIdRevisionIdOrderByIdRoleAsc(revisionId);
    }

    private List<BlobReferenceInput> toBlobReferenceInputs(List<VaultObjectRevisionBlob> blobReferences) {
        return blobReferences.stream()
                .map(reference -> new BlobReferenceInput(
                        reference.getBlobId(),
                        reference.getId().getRole()
                ))
                .toList();
    }

    private Vault loadVaultOrThrow(UUID vaultId) {
        return vaultRepository.findById(vaultId)
                .orElseThrow(() -> new ResourceNotFoundException("Vault not found"));
    }

    private String normalizeEmail(String email) {
        return email == null ? "" : email.trim();
    }

    private UserKeyMaterial loadUserKeyMaterialOrThrow(UUID userId) {
        return userKeyMaterialRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User key material not found"));
    }

    private String loadUserEmail(UUID userId) {
        if (userId == null) {
            return null;
        }

        return userRepository.findById(userId)
                .map(User::getEmail)
                .orElse(null);
    }

    private Map<UUID, String> loadUserEmailsByIds(List<UUID> userIds) {
        if (userIds.isEmpty()) {
            return Map.of();
        }

        return userRepository.findAllById(userIds).stream()
                .collect(Collectors.toMap(
                        User::getUserId,
                        User::getEmail
                ));
    }

    private record EnvelopeLookupKey(
            UUID vaultId,
            int vaultKeyVersion
    ) {
    }

    private VaultMemberResponse toVaultMemberResponse(
            VaultMember member,
            Map<UUID, User> usersById
    ) {
        User user = usersById.get(member.getId().getUserId());
        String email = user != null ? user.getEmail() : null;

        return new VaultMemberResponse(
                member.getId().getUserId(),
                email,
                member.getRole(),
                member.getStatus(),
                member.getJoinedAt(),
                member.getExpiresAt(),
                member.getRevokedAt()
        );
    }

    private Map<UUID, User> loadCreatorsById(List<VaultInvite> invites) {
        List<UUID> creatorIds = invites.stream()
                .map(VaultInvite::getCreatedByUserId)
                .distinct()
                .toList();

        return userRepository.findAllById(creatorIds).stream()
                .collect(Collectors.toMap(
                        User::getUserId,
                        Function.identity()
                ));
    }

    private List<IncomingVaultInviteResponse> mapIncomingInvites(
            List<VaultInvite> invites,
            Map<UUID, User> creatorsById
    ) {
        return invites.stream()
                .map(invite -> toIncomingInviteResponse(invite, creatorsById))
                .toList();
    }

    private IncomingVaultInviteResponse toIncomingInviteResponse(
            VaultInvite invite,
            Map<UUID, User> creatorsById
    ) {
        User creator = creatorsById.get(invite.getCreatedByUserId());
        String createdByEmail = creator != null ? creator.getEmail() : null;

        return new IncomingVaultInviteResponse(
                invite.getInviteId(),
                invite.getVaultId(),
                invite.getCreatedByUserId(),
                createdByEmail,
                invite.getInviteeEmail(),
                invite.getRole(),
                invite.getStatus(),
                invite.getCreatedAt(),
                invite.getExpiresAt(),
                invite.getAcceptedAt(),
                invite.getRevokedAt()
        );
    }

    @Transactional(readOnly = true)
    public ListVaultSharingMaterialsResponse getVaultSharingMaterials(UUID vaultId, Jwt jwt) {
        UUID currentUserId = UUID.fromString(jwt.getSubject());
        OffsetDateTime now = OffsetDateTime.now();

        vaultAccessService.requireOwnerMembership(vaultId, currentUserId, now);

        List<VaultMember> activeMembers = vaultMemberRepository
                .findByIdVaultIdAndStatusAndRevokedAtIsNullOrderByJoinedAtAsc(
                        vaultId,
                        VaultMemberStatus.ACTIVE
                );

        List<UUID> userIds = activeMembers.stream()
                .map(member -> member.getId().getUserId())
                .toList();

        Map<UUID, User> usersById = userRepository.findAllById(userIds).stream()
                .collect(Collectors.toMap(
                        User::getUserId,
                        Function.identity()
                ));

        Map<UUID, UserKeyMaterial> keyMaterialsById = userKeyMaterialRepository.findAllById(userIds).stream()
                .collect(Collectors.toMap(
                        UserKeyMaterial::getUserId,
                        Function.identity()
                ));

        List<VaultSharingMaterialResponse> items = activeMembers.stream()
                .map(member -> toVaultSharingMaterialResponse(member, usersById, keyMaterialsById))
                .toList();

        return new ListVaultSharingMaterialsResponse(vaultId, items);
    }

    private VaultSharingMaterialResponse toVaultSharingMaterialResponse(
            VaultMember member,
            Map<UUID, User> usersById,
            Map<UUID, UserKeyMaterial> keyMaterialsById
    ) {
        UUID userId = member.getId().getUserId();

        User user = usersById.get(userId);
        if (user == null) {
            throw new ResourceNotFoundException("User not found for vault member " + userId);
        }

        UserKeyMaterial keyMaterial = keyMaterialsById.get(userId);
        if (keyMaterial == null) {
            throw new ResourceNotFoundException("User key material not found for vault member " + userId);
        }

        String publicEncryptionKeyBase64 = Base64.getEncoder().encodeToString(
                keyMaterial.getPublicEncryptionKey()
        );

        return new VaultSharingMaterialResponse(
                userId,
                user.getEmail(),
                member.getRole(),
                publicEncryptionKeyBase64,
                keyMaterial.getEncryptionKeyVersion()
        );
    }
}
