package ru.dmitrysvirgunov.passwordmanager.vault.controller;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import ru.dmitrysvirgunov.passwordmanager.vault.dto.request.*;
import ru.dmitrysvirgunov.passwordmanager.vault.dto.response.command.*;
import ru.dmitrysvirgunov.passwordmanager.vault.dto.response.list.*;
import ru.dmitrysvirgunov.passwordmanager.vault.dto.response.membership.VaultInviteeKeyMaterialResponse;
import ru.dmitrysvirgunov.passwordmanager.vault.dto.response.object.VaultObjectRevisionResponse;
import ru.dmitrysvirgunov.passwordmanager.vault.dto.response.object.VaultObjectSnapshotResponse;
import ru.dmitrysvirgunov.passwordmanager.vault.dto.response.sync.GetUserSyncResponse;
import ru.dmitrysvirgunov.passwordmanager.vault.dto.response.sync.GetVaultSyncResponse;
import ru.dmitrysvirgunov.passwordmanager.vault.dto.response.vault.VaultDetailsResponse;
import ru.dmitrysvirgunov.passwordmanager.vault.mapper.*;
import ru.dmitrysvirgunov.passwordmanager.vault.model.*;
import ru.dmitrysvirgunov.passwordmanager.vault.service.*;

import java.net.URI;
import java.util.UUID;

@RestController
@RequestMapping("/vaults")
@RequiredArgsConstructor
@Validated
public class VaultController {

    private final VaultCommandService vaultCommandService;
    private final VaultObjectCommandService vaultObjectCommandService;
    private final VaultQueryService vaultQueryService;
    private final VaultSyncService vaultSyncService;
    private final VaultSharingService vaultSharingService;
    private final VaultRotationService vaultRotationService;

    private final CreateVaultRequestMapper createVaultRequestMapper;
    private final CreateVaultObjectRequestMapper createVaultObjectRequestMapper;
    private final UpdateVaultObjectRequestMapper updateVaultObjectRequestMapper;
    private final DeleteVaultObjectRequestMapper deleteVaultObjectRequestMapper;
    private final CreateVaultInviteRequestMapper createVaultInviteRequestMapper;
    private final RotateVaultKeyRequestMapper rotateVaultKeyRequestMapper;

    @PostMapping
    public ResponseEntity<CreateVaultResponse> createVault(
            @Valid @RequestBody CreateVaultRequest request,
            @AuthenticationPrincipal Jwt jwt
    ) {
        CreateVaultInput input = createVaultRequestMapper.toInput(request);
        CreateVaultResponse response = vaultCommandService.createVault(input, jwt);

        URI location = ServletUriComponentsBuilder
                .fromCurrentRequest()
                .path("/{vaultId}")
                .buildAndExpand(response.vaultId())
                .toUri();

        return ResponseEntity.created(location).body(response);
    }

    @PostMapping("/{vaultId}/objects")
    public ResponseEntity<CreateVaultObjectResponse> createObject(
            @PathVariable UUID vaultId,
            @Valid @RequestBody CreateVaultObjectRequest request,
            @AuthenticationPrincipal Jwt jwt
    ) {
        CreateVaultObjectInput input = createVaultObjectRequestMapper.toInput(request);
        CreateVaultObjectResponse response = vaultObjectCommandService.createObject(vaultId, input, jwt);

        URI location = ServletUriComponentsBuilder
                .fromCurrentRequest()
                .path("/{objectId}")
                .buildAndExpand(response.objectId())
                .toUri();

        return ResponseEntity.created(location).body(response);
    }

    @PutMapping("/{vaultId}/objects/{objectId}")
    public ResponseEntity<UpdateVaultObjectResponse> updateObject(
            @PathVariable UUID vaultId,
            @PathVariable UUID objectId,
            @Valid @RequestBody UpdateVaultObjectRequest request,
            @AuthenticationPrincipal Jwt jwt
    ) {
        UpdateVaultObjectInput input = updateVaultObjectRequestMapper.toInput(request);
        UpdateVaultObjectResponse response = vaultObjectCommandService.updateObject(vaultId, objectId, input, jwt);
        return ResponseEntity.ok(response);
    }

    @DeleteMapping("/{vaultId}/objects/{objectId}")
    public ResponseEntity<DeleteVaultObjectResponse> deleteObject(
            @PathVariable UUID vaultId,
            @PathVariable UUID objectId,
            @Valid @RequestBody DeleteVaultObjectRequest request,
            @AuthenticationPrincipal Jwt jwt
    ) {
        DeleteVaultObjectInput input = deleteVaultObjectRequestMapper.toInput(request);
        DeleteVaultObjectResponse response = vaultObjectCommandService.deleteObject(vaultId, objectId, input, jwt);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/{vaultId}/objects")
    public ResponseEntity<ListVaultObjectsResponse> getVaultObjects(
            @PathVariable UUID vaultId,
            @RequestParam(name = "includeDeleted", defaultValue = "false") boolean includeDeleted,
            @RequestParam(name = "page", defaultValue = "1") @Min(1) int page,
            @RequestParam(name = "size", defaultValue = "24") @Min(1) @Max(100) int size,
            @AuthenticationPrincipal Jwt jwt
    ) {
        return ResponseEntity.ok(
                vaultQueryService.getVaultObjects(vaultId, includeDeleted, page, size, jwt)
        );
    }

    @GetMapping("/{vaultId}/objects/{objectId}")
    public ResponseEntity<VaultObjectSnapshotResponse> getVaultObject(
            @PathVariable UUID vaultId,
            @PathVariable UUID objectId,
            @RequestParam(name = "includeDeleted", defaultValue = "false") boolean includeDeleted,
            @AuthenticationPrincipal Jwt jwt
    ) {
        return ResponseEntity.ok(
                vaultQueryService.getVaultObject(vaultId, objectId, includeDeleted, jwt)
        );
    }

    @GetMapping("/{vaultId}/objects/{objectId}/revisions")
    public ResponseEntity<ListVaultObjectRevisionsResponse> getVaultObjectRevisions(
            @PathVariable UUID vaultId,
            @PathVariable UUID objectId,
            @AuthenticationPrincipal Jwt jwt
    ) {
        return ResponseEntity.ok(
                vaultQueryService.getVaultObjectRevisions(vaultId, objectId, jwt)
        );
    }

    @GetMapping("/{vaultId}/objects/{objectId}/revisions/{version}")
    public ResponseEntity<VaultObjectRevisionResponse> getVaultObjectRevision(
            @PathVariable UUID vaultId,
            @PathVariable UUID objectId,
            @PathVariable int version,
            @AuthenticationPrincipal Jwt jwt
    ) {
        return ResponseEntity.ok(
                vaultQueryService.getVaultObjectRevision(vaultId, objectId, version, jwt)
        );
    }

    @GetMapping("/{vaultId}/sync")
    public ResponseEntity<GetVaultSyncResponse> getVaultSync(
            @PathVariable UUID vaultId,
            @RequestParam(name = "afterSeq", defaultValue = "0") long afterSeq,
            @AuthenticationPrincipal Jwt jwt
    ) {
        return ResponseEntity.ok(
                vaultSyncService.getVaultSync(vaultId, afterSeq, jwt)
        );
    }

    @GetMapping("/user-sync")
    public ResponseEntity<GetUserSyncResponse> getUserSync(
            @RequestParam(name = "afterSeq", defaultValue = "0") long afterSeq,
            @AuthenticationPrincipal Jwt jwt
    ) {
        return ResponseEntity.ok(
                vaultSyncService.getUserSync(afterSeq, jwt)
        );
    }

    @GetMapping
    public ResponseEntity<ListVaultsResponse> getVaults(
            @RequestParam(name = "page", defaultValue = "1") @Min(1) int page,
            @RequestParam(name = "size", defaultValue = "12") @Min(1) @Max(100) int size,
            @AuthenticationPrincipal Jwt jwt
    ) {
        return ResponseEntity.ok(
                vaultQueryService.getVaults(page, size, jwt)
        );
    }

    @GetMapping("/{vaultId}")
    public ResponseEntity<VaultDetailsResponse> getVault(
            @PathVariable UUID vaultId,
            @AuthenticationPrincipal Jwt jwt
    ) {
        return ResponseEntity.ok(
                vaultQueryService.getVault(vaultId, jwt)
        );
    }

    @DeleteMapping("/{vaultId}")
    public ResponseEntity<Void> deleteVault(
            @PathVariable UUID vaultId,
            @AuthenticationPrincipal Jwt jwt
    ) {
        vaultCommandService.deleteVault(vaultId, UUID.fromString(jwt.getSubject()));
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/{vaultId}/invites")
    public ResponseEntity<CreateVaultInviteResponse> createInvite(
            @PathVariable UUID vaultId,
            @Valid @RequestBody CreateVaultInviteRequest request,
            @AuthenticationPrincipal Jwt jwt
    ) {
        CreateVaultInviteInput input = createVaultInviteRequestMapper.toInput(request);

        CreateVaultInviteResponse response = vaultSharingService.createInvite(
                vaultId,
                input,
                UUID.fromString(jwt.getSubject())
        );

        URI location = ServletUriComponentsBuilder
                .fromCurrentRequest()
                .path("/{inviteId}")
                .buildAndExpand(response.inviteId())
                .toUri();

        return ResponseEntity.created(location).body(response);
    }

    @GetMapping("/{vaultId}/members")
    public ResponseEntity<ListVaultMembersResponse> getVaultMembers(
            @PathVariable UUID vaultId,
            @AuthenticationPrincipal Jwt jwt
    ) {
        return ResponseEntity.ok(
                vaultQueryService.getVaultMembers(vaultId, jwt)
        );
    }

    @GetMapping("/{vaultId}/invites")
    public ResponseEntity<ListVaultInvitesResponse> getVaultInvites(
            @PathVariable UUID vaultId,
            @AuthenticationPrincipal Jwt jwt
    ) {
        return ResponseEntity.ok(
                vaultQueryService.getVaultInvites(vaultId, jwt)
        );
    }

    @GetMapping("/{vaultId}/invitee-key-material")
    public ResponseEntity<VaultInviteeKeyMaterialResponse> getVaultInviteeKeyMaterial(
            @PathVariable UUID vaultId,
            @RequestParam @NotBlank String email,
            @AuthenticationPrincipal Jwt jwt
    ) {
        return ResponseEntity.ok(
                vaultQueryService.getVaultInviteeKeyMaterial(vaultId, email, jwt)
        );
    }

    @PostMapping("/invites/{inviteId}/accept")
    public ResponseEntity<Void> acceptInvite(
            @PathVariable UUID inviteId,
            @AuthenticationPrincipal Jwt jwt
    ) {
        vaultSharingService.acceptInvite(inviteId, UUID.fromString(jwt.getSubject()));
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/{vaultId}/invites/{inviteId}/revoke")
    public ResponseEntity<Void> revokeInvite(
            @PathVariable UUID vaultId,
            @PathVariable UUID inviteId,
            @AuthenticationPrincipal Jwt jwt
    ) {
        vaultSharingService.revokeInvite(vaultId, inviteId, UUID.fromString(jwt.getSubject()));
        return ResponseEntity.noContent().build();
    }

    @PatchMapping("/{vaultId}/members/{userId}/role")
    public ResponseEntity<Void> changeMemberRole(
            @PathVariable UUID vaultId,
            @PathVariable UUID userId,
            @Valid @RequestBody ChangeVaultMemberRoleRequest request,
            @AuthenticationPrincipal Jwt jwt
    ) {
        ChangeVaultMemberRoleInput input = new ChangeVaultMemberRoleInput(request.role());

        vaultSharingService.changeMemberRole(
                vaultId,
                userId,
                input,
                UUID.fromString(jwt.getSubject())
        );

        return ResponseEntity.noContent().build();
    }

    @PostMapping("/{vaultId}/members/{userId}/transfer-ownership")
    public ResponseEntity<Void> transferOwnership(
            @PathVariable UUID vaultId,
            @PathVariable UUID userId,
            @AuthenticationPrincipal Jwt jwt
    ) {
        vaultSharingService.transferOwnership(
                vaultId,
                userId,
                UUID.fromString(jwt.getSubject())
        );

        return ResponseEntity.noContent().build();
    }

    @PostMapping("/{vaultId}/members/{userId}/revoke")
    public ResponseEntity<Void> revokeMember(
            @PathVariable UUID vaultId,
            @PathVariable UUID userId,
            @AuthenticationPrincipal Jwt jwt
    ) {
        vaultSharingService.revokeMember(vaultId, userId, UUID.fromString(jwt.getSubject()));
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/invites/incoming")
    public ResponseEntity<ListIncomingVaultInvitesResponse> getIncomingInvites(
            @AuthenticationPrincipal Jwt jwt
    ) {
        return ResponseEntity.ok(
                vaultQueryService.getIncomingInvites(jwt)
        );
    }

    @PostMapping("/invites/{inviteId}/decline")
    public ResponseEntity<Void> declineInvite(
            @PathVariable UUID inviteId,
            @AuthenticationPrincipal Jwt jwt
    ) {
        vaultSharingService.declineInvite(inviteId, UUID.fromString(jwt.getSubject()));
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/{vaultId}/envelopes")
    public ResponseEntity<ListVaultEnvelopesResponse> getVaultEnvelopes(
            @PathVariable UUID vaultId,
            @AuthenticationPrincipal Jwt jwt
    ) {
        return ResponseEntity.ok(
                vaultQueryService.getVaultEnvelopes(vaultId, jwt)
        );
    }

    @GetMapping("/{vaultId}/sharing-materials")
    public ResponseEntity<ListVaultSharingMaterialsResponse> getVaultSharingMaterials(
            @PathVariable UUID vaultId,
            @AuthenticationPrincipal Jwt jwt
    ) {
        return ResponseEntity.ok(
                vaultQueryService.getVaultSharingMaterials(vaultId, jwt)
        );
    }

    @PostMapping("/{vaultId}/rotate-key")
    public ResponseEntity<RotateVaultKeyResponse> rotateVaultKey(
            @PathVariable UUID vaultId,
            @Valid @RequestBody RotateVaultKeyRequest request,
            @AuthenticationPrincipal Jwt jwt
    ) {
        RotateVaultKeyInput input = rotateVaultKeyRequestMapper.toInput(request);

        RotateVaultKeyResponse response = vaultRotationService.rotateVaultKey(
                vaultId,
                input,
                UUID.fromString(jwt.getSubject())
        );

        return ResponseEntity.ok(response);
    }
}
