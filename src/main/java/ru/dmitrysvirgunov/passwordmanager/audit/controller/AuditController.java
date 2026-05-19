package ru.dmitrysvirgunov.passwordmanager.audit.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import ru.dmitrysvirgunov.passwordmanager.audit.dto.response.AuditAnchorVerificationResponse;
import ru.dmitrysvirgunov.passwordmanager.audit.dto.response.AuditChainVerificationResponse;
import ru.dmitrysvirgunov.passwordmanager.audit.dto.response.AuditIntegrityResponse;
import ru.dmitrysvirgunov.passwordmanager.audit.dto.response.ListAuditEventsResponse;
import ru.dmitrysvirgunov.passwordmanager.audit.model.AuditEventVerificationResult;
import ru.dmitrysvirgunov.passwordmanager.audit.service.AuditAccessService;
import ru.dmitrysvirgunov.passwordmanager.audit.service.AuditAnchorService;
import ru.dmitrysvirgunov.passwordmanager.audit.service.AuditQueryService;
import ru.dmitrysvirgunov.passwordmanager.audit.service.AuditVerificationService;

import java.util.UUID;

@RestController
@RequestMapping("/audit")
@RequiredArgsConstructor
public class AuditController {

    private final AuditQueryService auditQueryService;
    private final AuditVerificationService auditVerificationService;
    private final AuditAccessService auditAccessService;
    private final AuditAnchorService auditAnchorService;

    @GetMapping("/vaults/{vaultId}/events")
    public ResponseEntity<ListAuditEventsResponse> getVaultEvents(
            @PathVariable UUID vaultId,
            @RequestParam(defaultValue = "1") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(required = false) String eventType,
            @RequestParam(required = false) String query,
            @RequestParam(required = false) String actor,
            @RequestParam(required = false) String affected,
            @RequestParam(required = false) Integer lastDays,
            @RequestParam(defaultValue = "false") boolean problemsOnly,
            @AuthenticationPrincipal Jwt jwt
    ) {
        auditAccessService.requireVaultAuditRead(vaultId, jwt);
        return ResponseEntity.ok(auditQueryService.getVaultEvents(
                vaultId,
                page,
                size,
                eventType,
                query,
                actor,
                affected,
                lastDays,
                problemsOnly
        ));
    }

    @GetMapping("/users/{userId}/events")
    public ResponseEntity<ListAuditEventsResponse> getUserEvents(
            @PathVariable UUID userId,
            @RequestParam(defaultValue = "1") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(required = false) String eventType,
            @RequestParam(required = false) String query,
            @RequestParam(required = false) String actor,
            @RequestParam(required = false) String affected,
            @RequestParam(required = false) Integer lastDays,
            @RequestParam(defaultValue = "false") boolean problemsOnly,
            @AuthenticationPrincipal Jwt jwt
    ) {
        auditAccessService.requireUserAuditRead(userId, jwt);
        return ResponseEntity.ok(auditQueryService.getUserEvents(
                userId,
                page,
                size,
                eventType,
                query,
                actor,
                affected,
                lastDays,
                problemsOnly
        ));
    }

    @GetMapping("/events/{eventId}/verify")
    public ResponseEntity<AuditEventVerificationResult> verifyEvent(
            @PathVariable Long eventId,
            @AuthenticationPrincipal Jwt jwt
    ) {
        auditAccessService.requireEventAuditRead(eventId, jwt);
        return ResponseEntity.ok(auditVerificationService.verifyEvent(eventId));
    }

    @GetMapping("/vaults/{vaultId}/verify-chain")
    public ResponseEntity<AuditChainVerificationResponse> verifyVaultChain(
            @PathVariable UUID vaultId,
            @AuthenticationPrincipal Jwt jwt
    ) {
        auditAccessService.requireVaultAuditRead(vaultId, jwt);
        return ResponseEntity.ok(auditQueryService.verifyVaultChain(vaultId));
    }

    @GetMapping("/users/{userId}/verify-chain")
    public ResponseEntity<AuditChainVerificationResponse> verifyUserChain(
            @PathVariable UUID userId,
            @AuthenticationPrincipal Jwt jwt
    ) {
        auditAccessService.requireUserAuditRead(userId, jwt);
        return ResponseEntity.ok(auditQueryService.verifyUserChain(userId));
    }

    @GetMapping("/vaults/{vaultId}/verify-anchor")
    public ResponseEntity<AuditAnchorVerificationResponse> verifyVaultAnchor(
            @PathVariable UUID vaultId,
            @AuthenticationPrincipal Jwt jwt
    ) {
        auditAccessService.requireVaultAuditRead(vaultId, jwt);
        return ResponseEntity.ok(auditAnchorService.verifyVaultAnchor(vaultId));
    }

    @GetMapping("/users/{userId}/verify-anchor")
    public ResponseEntity<AuditAnchorVerificationResponse> verifyUserAnchor(
            @PathVariable UUID userId,
            @AuthenticationPrincipal Jwt jwt
    ) {
        auditAccessService.requireUserAuditRead(userId, jwt);
        return ResponseEntity.ok(auditAnchorService.verifyUserAnchor(userId));
    }

    @GetMapping("/vaults/{vaultId}/integrity")
    public ResponseEntity<AuditIntegrityResponse> getVaultIntegrity(
            @PathVariable UUID vaultId,
            @AuthenticationPrincipal Jwt jwt
    ) {
        auditAccessService.requireVaultAuditRead(vaultId, jwt);
        return ResponseEntity.ok(auditAnchorService.getVaultIntegrity(vaultId));
    }

    @GetMapping("/users/{userId}/integrity")
    public ResponseEntity<AuditIntegrityResponse> getUserIntegrity(
            @PathVariable UUID userId,
            @AuthenticationPrincipal Jwt jwt
    ) {
        auditAccessService.requireUserAuditRead(userId, jwt);
        return ResponseEntity.ok(auditAnchorService.getUserIntegrity(userId));
    }
}
