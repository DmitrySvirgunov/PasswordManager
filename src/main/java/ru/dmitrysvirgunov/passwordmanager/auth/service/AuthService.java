package ru.dmitrysvirgunov.passwordmanager.auth.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.dmitrysvirgunov.passwordmanager.audit.service.AuditService;
import ru.dmitrysvirgunov.passwordmanager.auth.dto.request.PreloginRequest;
import ru.dmitrysvirgunov.passwordmanager.auth.dto.response.*;
import ru.dmitrysvirgunov.passwordmanager.auth.entity.*;
import ru.dmitrysvirgunov.passwordmanager.auth.event.RegistrationVerificationEmailRequestedEvent;
import ru.dmitrysvirgunov.passwordmanager.auth.mapper.KdfParamsResponseMapper;
import ru.dmitrysvirgunov.passwordmanager.auth.model.*;
import ru.dmitrysvirgunov.passwordmanager.auth.repository.*;
import ru.dmitrysvirgunov.passwordmanager.common.exception.*;
import ru.dmitrysvirgunov.passwordmanager.common.security.HashingService;
import ru.dmitrysvirgunov.passwordmanager.common.security.JwtTokenService;
import ru.dmitrysvirgunov.passwordmanager.common.security.ServerAuthHashingService;
import ru.dmitrysvirgunov.passwordmanager.common.security.ServerAuthHashingService.StoredAuthSecret;
import ru.dmitrysvirgunov.passwordmanager.common.web.ClientRequestMetadata;
import ru.dmitrysvirgunov.passwordmanager.config.RegistrationProperties;
import ru.dmitrysvirgunov.passwordmanager.vault.entity.VaultInvite;
import ru.dmitrysvirgunov.passwordmanager.vault.entity.VaultKeyEnvelope;
import ru.dmitrysvirgunov.passwordmanager.vault.entity.VaultMember;
import ru.dmitrysvirgunov.passwordmanager.vault.model.VaultInviteStatus;
import ru.dmitrysvirgunov.passwordmanager.vault.model.VaultMemberRole;
import ru.dmitrysvirgunov.passwordmanager.vault.model.VaultMemberStatus;
import ru.dmitrysvirgunov.passwordmanager.vault.repository.VaultInviteRepository;
import ru.dmitrysvirgunov.passwordmanager.vault.repository.VaultKeyEnvelopeRepository;
import ru.dmitrysvirgunov.passwordmanager.vault.repository.VaultMemberRepository;
import ru.dmitrysvirgunov.passwordmanager.vault.repository.VaultRepository;
import ru.dmitrysvirgunov.passwordmanager.vault.service.VaultSyncService;

import java.time.OffsetDateTime;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private static final long REGISTRATION_TOKEN_TTL_MINUTES = 30;
    private static final int CURRENT_AUTH_VERSION = 2;
    private static final int CURRENT_ACCOUNT_ROOT_VERSION = 1;
    private static final int CURRENT_ENCRYPTION_KEY_VERSION = 1;
    private static final int CURRENT_SIGNING_KEY_VERSION = 1;
    private static final int CURRENT_ENVELOPE_VERSION = 1;
    private static final long REFRESH_SESSION_TTL_DAYS = 30;
    private static final String DEFAULT_CLIENT_KDF_ALGORITHM = "ARGON2ID";
    private static final int DEFAULT_CLIENT_KDF_ITERATIONS = 3;
    private static final int DEFAULT_CLIENT_KDF_MEMORY_KB = 65536;
    private static final int DEFAULT_CLIENT_KDF_PARALLELISM = 1;


    private final UserRepository userRepository;
    private final PendingRegistrationRepository pendingRegistrationRepository;
    private final VerificationTokenService verificationTokenService;
    private final HashingService hashingService;
    private final ServerAuthHashingService serverAuthHashingService;
    private final RegistrationAntiAbuseService registrationAntiAbuseService;
    private final LoginAntiAbuseService loginAntiAbuseService;
    private final PreloginAntiAbuseService preloginAntiAbuseService;
    private final VerifyEmailAntiAbuseService verifyEmailAntiAbuseService;
    private final UserAuthRepository userAuthRepository;
    private final UserKeyMaterialRepository userKeyMaterialRepository;
    private final UserKeyMaterialHistoryRepository userKeyMaterialHistoryRepository;
    private final ApplicationEventPublisher eventPublisher;
    private final RegistrationProperties registrationProperties;
    private final UserSessionRepository userSessionRepository;
    private final SessionTokenService sessionTokenService;
    private final JwtTokenService jwtTokenService;
    private final AuditService auditService;
    private final KdfParamsResponseMapper kdfParamsResponseMapper;
    private final VaultMemberRepository vaultMemberRepository;
    private final VaultInviteRepository vaultInviteRepository;
    private final VaultKeyEnvelopeRepository vaultKeyEnvelopeRepository;
    private final VaultRepository vaultRepository;
    private final VaultSyncService vaultSyncService;

    @Transactional
    public RegisterResponse register(RegisterInput registerInput, ClientRequestMetadata metadata) {
        log.info("registration mode={}", registrationProperties.mode());
        return switch (registrationProperties.mode()) {
            case AUTO_ACTIVATE -> registerAndActivateImmediately(registerInput, metadata);
            case EMAIL_VERIFICATION -> registerWithPendingVerification(registerInput, metadata);
        };
    }

    private RegisterResponse registerWithPendingVerification(
            RegisterInput registerInput,
            ClientRequestMetadata metadata
    ) {
        OffsetDateTime now = OffsetDateTime.now();
        OffsetDateTime expiresAt = now.plusMinutes(REGISTRATION_TOKEN_TTL_MINUTES);

        String rawToken = verificationTokenService.generateRawToken();
        byte[] tokenHash = hashingService.hashVerificationToken(rawToken);
        StoredAuthSecret storedAuthSecret = serverAuthHashingService.hashForStorage(registerInput.authSecret());

        RegistrationHashes hashes = checkRegistrationAntiAbuse(registerInput, metadata);

        if (userRepository.existsByEmailIgnoreCaseAndStatusNot(registerInput.email(), UserStatus.DELETED)) {
            return new RegisterResponse(
                    registerInput.email(),
                    RegistrationStatus.REQUEST_ACCEPTED
            );
        }

        PendingRegistration pendingRegistration = pendingRegistrationRepository
                .findByEmailIgnoreCaseAndUsedAtIsNull(registerInput.email())
                .map(existing -> updatePendingRegistration(
                        existing,
                        registerInput,
                        storedAuthSecret,
                        tokenHash,
                        hashes.requestIpHash(),
                        hashes.userAgentHash(),
                        expiresAt,
                        now
                ))
                .orElseGet(() -> createPendingRegistration(
                        registerInput,
                        storedAuthSecret,
                        tokenHash,
                        hashes.requestIpHash(),
                        hashes.userAgentHash(),
                        expiresAt,
                        now
                ));

        try {
            pendingRegistrationRepository.saveAndFlush(pendingRegistration);
        } catch (DataIntegrityViolationException ex) {
            return new RegisterResponse(
                    registerInput.email(),
                    RegistrationStatus.REQUEST_ACCEPTED
            );
        }

        eventPublisher.publishEvent(
                new RegistrationVerificationEmailRequestedEvent(
                        registerInput.email(),
                        rawToken
                )
        );

        return new RegisterResponse(
                registerInput.email(),
                RegistrationStatus.REQUEST_ACCEPTED
        );
    }

    private RegisterResponse registerAndActivateImmediately(
            RegisterInput registerInput,
            ClientRequestMetadata metadata
    ) {
        if (userRepository.existsByEmailIgnoreCaseAndStatusNot(registerInput.email(), UserStatus.DELETED)) {
            throw new ResourceAlreadyExistsException("User with this email already exists");
        }

        OffsetDateTime now = OffsetDateTime.now();
        UUID userId = UUID.randomUUID();

        checkRegistrationAntiAbuse(registerInput, metadata);
        StoredAuthSecret storedAuthSecret = serverAuthHashingService.hashForStorage(registerInput.authSecret());

        User user = buildActiveUser(userId, registerInput.email(), now);
        UserAuth userAuth = buildUserAuth(
                userId,
                storedAuthSecret,
                registerInput.clientKdfParams(),
                now
        );
        UserKeyMaterial userKeyMaterial = buildUserKeyMaterial(
                userId,
                registerInput,
                now
        );

        try {
            userRepository.saveAndFlush(user);
        } catch (DataIntegrityViolationException ex) {
            throw new ResourceAlreadyExistsException("User with this email already exists");
        }

        userAuthRepository.save(userAuth);
        userKeyMaterialRepository.save(userKeyMaterial);

        auditService.appendUserRegistered(userId, now);

        return new RegisterResponse(
                registerInput.email(),
                RegistrationStatus.ACTIVE
        );
    }

    @Transactional
    public VerifyEmailResponse verifyEmail(String rawToken, ClientRequestMetadata metadata) {
        verifyEmailAntiAbuseService.checkAndRecord(
                hashingService.hashRequestIp(metadata.clientIp()),
                hashingService.hashUserAgent(metadata.userAgent())
        );

        OffsetDateTime now = OffsetDateTime.now();
        byte[] tokenHash = hashingService.hashVerificationToken(rawToken);

        PendingRegistration pendingRegistration = pendingRegistrationRepository
                .findByTokenHashAndUsedAtIsNull(tokenHash)
                .orElseThrow(() -> new TokenInvalidException("Verification token is invalid"));

        if (!pendingRegistration.getExpiresAt().isAfter(now)) {
            throw new TokenExpiredException("Verification token has expired");
        }

        if (userRepository.existsByEmailIgnoreCaseAndStatusNot(pendingRegistration.getEmail(), UserStatus.DELETED)) {
            throw new ResourceAlreadyExistsException("User with this email already exists");
        }

        UUID userId = UUID.randomUUID();

        User user = buildActiveUser(userId, pendingRegistration.getEmail(), now);
        UserAuth userAuth = buildUserAuth(
                userId,
                pendingRegistration,
                now
        );
        UserKeyMaterial userKeyMaterial = buildUserKeyMaterial(
                userId,
                pendingRegistration,
                now
        );

        pendingRegistration.setUsedAt(now);
        pendingRegistration.setUpdatedAt(now);

        try {
            userRepository.saveAndFlush(user);
        } catch (DataIntegrityViolationException ex) {
            throw new ResourceAlreadyExistsException("User with this email already exists");
        }

        userAuthRepository.save(userAuth);
        userKeyMaterialRepository.save(userKeyMaterial);

        auditService.appendUserRegistered(userId, now);

        return new VerifyEmailResponse(
                user.getEmail(),
                VerifyEmailStatus.VERIFIED
        );
    }

    private PendingRegistration createPendingRegistration(
            RegisterInput input,
            StoredAuthSecret storedAuthSecret,
            byte[] tokenHash,
            byte[] requestIpHash,
            byte[] userAgentHash,
            OffsetDateTime expiresAt,
            OffsetDateTime now
    ) {
        PendingRegistration pendingRegistration = PendingRegistration.builder()
                .pendingRegistrationId(UUID.randomUUID())
                .email(input.email())
                .createdAt(now)
                .build();

        applyPendingRegistrationData(
                pendingRegistration,
                input,
                storedAuthSecret,
                tokenHash,
                requestIpHash,
                userAgentHash,
                expiresAt,
                now
        );

        return pendingRegistration;
    }

    private PendingRegistration updatePendingRegistration(
            PendingRegistration existing,
            RegisterInput input,
            StoredAuthSecret storedAuthSecret,
            byte[] tokenHash,
            byte[] requestIpHash,
            byte[] userAgentHash,
            OffsetDateTime expiresAt,
            OffsetDateTime now
    ) {
        applyPendingRegistrationData(
                existing,
                input,
                storedAuthSecret,
                tokenHash,
                requestIpHash,
                userAgentHash,
                expiresAt,
                now
        );
        return existing;
    }

    private void applyPendingRegistrationData(
            PendingRegistration target,
            RegisterInput input,
            StoredAuthSecret storedAuthSecret,
            byte[] tokenHash,
            byte[] requestIpHash,
            byte[] userAgentHash,
            OffsetDateTime expiresAt,
            OffsetDateTime now
    ) {
        target.setAuthHash(storedAuthSecret.authHash());
        target.setAuthSalt(storedAuthSecret.authSalt());
        target.setAuthHashParams(storedAuthSecret.authHashParams());
        target.setClientKdfParams(input.clientKdfParams());

        target.setWrappedAccountRootKey(input.wrappedAccountRootKey());
        target.setAccountRootWrapParams(input.accountRootWrapParams());
        target.setAccountRootVersion(CURRENT_ACCOUNT_ROOT_VERSION);

        target.setPublicEncryptionKey(input.publicEncryptionKey());
        target.setEncryptedPrivateEncryptionKey(input.encryptedPrivateEncryptionKey());
        target.setEncryptionKeyParams(input.encryptionKeyParams());
        target.setEncryptionKeyVersion(CURRENT_ENCRYPTION_KEY_VERSION);

        target.setPublicSigningKey(input.publicSigningKey());
        target.setEncryptedPrivateSigningKey(input.encryptedPrivateSigningKey());
        target.setSigningKeyParams(input.signingKeyParams());
        target.setSigningKeyVersion(CURRENT_SIGNING_KEY_VERSION);

        target.setTokenHash(tokenHash);
        target.setRequestIpHash(requestIpHash);
        target.setUserAgentHash(userAgentHash);
        target.setExpiresAt(expiresAt);
        target.setUpdatedAt(now);
        target.setUsedAt(null);
    }

    private User buildActiveUser(UUID userId, String email, OffsetDateTime now) {
        return User.builder()
                .userId(userId)
                .email(email)
                .status(UserStatus.ACTIVE)
                .emailVerifiedAt(now)
                .createdAt(now)
                .updatedAt(now)
                .build();
    }

    private UserAuth buildUserAuth(
            UUID userId,
            StoredAuthSecret storedAuthSecret,
            KdfParams clientKdfParams,
            OffsetDateTime now
    ) {
        return UserAuth.builder()
                .userId(userId)
                .authHash(storedAuthSecret.authHash())
                .authSalt(storedAuthSecret.authSalt())
                .authHashParams(storedAuthSecret.authHashParams())
                .clientKdfParams(clientKdfParams)
                .authVersion(CURRENT_AUTH_VERSION)
                .passwordChangedAt(now)
                .updatedAt(now)
                .build();
    }

    private UserAuth buildUserAuth(UUID userId, PendingRegistration pendingRegistration, OffsetDateTime now) {
        return UserAuth.builder()
                .userId(userId)
                .authHash(pendingRegistration.getAuthHash())
                .authSalt(pendingRegistration.getAuthSalt())
                .authHashParams(pendingRegistration.getAuthHashParams())
                .clientKdfParams(pendingRegistration.getClientKdfParams())
                .authVersion(CURRENT_AUTH_VERSION)
                .passwordChangedAt(now)
                .updatedAt(now)
                .build();
    }

    private UserKeyMaterial buildUserKeyMaterial(
            UUID userId,
            RegisterInput input,
            OffsetDateTime now
    ) {
        return UserKeyMaterial.builder()
                .userId(userId)

                .wrappedAccountRootKey(input.wrappedAccountRootKey())
                .accountRootWrapParams(input.accountRootWrapParams())
                .accountRootVersion(CURRENT_ACCOUNT_ROOT_VERSION)

                .publicEncryptionKey(input.publicEncryptionKey())
                .encryptedPrivateEncryptionKey(input.encryptedPrivateEncryptionKey())
                .encryptionKeyParams(input.encryptionKeyParams())
                .encryptionKeyVersion(CURRENT_ENCRYPTION_KEY_VERSION)

                .publicSigningKey(input.publicSigningKey())
                .encryptedPrivateSigningKey(input.encryptedPrivateSigningKey())
                .signingKeyParams(input.signingKeyParams())
                .signingKeyVersion(CURRENT_SIGNING_KEY_VERSION)

                .createdAt(now)
                .rotatedAt(null)
                .build();
    }

    private UserKeyMaterial buildUserKeyMaterial(
            UUID userId,
            PendingRegistration pendingRegistration,
            OffsetDateTime now
    ) {
        return UserKeyMaterial.builder()
                .userId(userId)

                .wrappedAccountRootKey(pendingRegistration.getWrappedAccountRootKey())
                .accountRootWrapParams(pendingRegistration.getAccountRootWrapParams())
                .accountRootVersion(pendingRegistration.getAccountRootVersion())

                .publicEncryptionKey(pendingRegistration.getPublicEncryptionKey())
                .encryptedPrivateEncryptionKey(pendingRegistration.getEncryptedPrivateEncryptionKey())
                .encryptionKeyParams(pendingRegistration.getEncryptionKeyParams())
                .encryptionKeyVersion(pendingRegistration.getEncryptionKeyVersion())

                .publicSigningKey(pendingRegistration.getPublicSigningKey())
                .encryptedPrivateSigningKey(pendingRegistration.getEncryptedPrivateSigningKey())
                .signingKeyParams(pendingRegistration.getSigningKeyParams())
                .signingKeyVersion(pendingRegistration.getSigningKeyVersion())

                .createdAt(now)
                .rotatedAt(null)
                .build();
    }

    private RegistrationHashes checkRegistrationAntiAbuse(
            RegisterInput input,
            ClientRequestMetadata metadata
    ) {
        byte[] emailHash = hashingService.hashEmailForAbuse(input.email());
        byte[] requestIpHash = hashingService.hashRequestIp(metadata.clientIp());
        byte[] userAgentHash = hashingService.hashUserAgent(metadata.userAgent());

        registrationAntiAbuseService.checkAndRecord(emailHash, requestIpHash, userAgentHash);

        return new RegistrationHashes(emailHash, requestIpHash, userAgentHash);
    }

    private record RegistrationHashes(
            byte[] emailHash,
            byte[] requestIpHash,
            byte[] userAgentHash
    ) {
    }

    @Transactional
    public AuthTokensResponse login(LoginInput input, ClientRequestMetadata metadata) {
        byte[] emailHash = hashingService.hashEmailForAbuse(input.email());
        byte[] requestIpHash = hashingService.hashRequestIp(metadata.clientIp());
        byte[] userAgentHash = hashingService.hashUserAgent(metadata.userAgent());

        loginAntiAbuseService.checkAllowed(emailHash, requestIpHash, userAgentHash);

        User user = userRepository.findByEmailIgnoreCaseAndStatusNot(input.email(), UserStatus.DELETED)
                .orElseThrow(() -> {
                    loginAntiAbuseService.recordFailure(
                            null,
                            emailHash,
                            requestIpHash,
                            userAgentHash,
                            AuthAttemptReasonCode.UNKNOWN_EMAIL
                    );
                    return new AuthenticationException("Invalid credentials");
                });

        if (user.getStatus() != UserStatus.ACTIVE) {
            loginAntiAbuseService.recordFailure(
                    user.getUserId(),
                    emailHash,
                    requestIpHash,
                    userAgentHash,
                    AuthAttemptReasonCode.INVALID_CREDENTIALS
            );
            throw new AuthenticationException("Invalid credentials");
        }

        UserAuth userAuth = userAuthRepository.findById(user.getUserId())
                .orElseThrow(() -> {
                    loginAntiAbuseService.recordFailure(
                            user.getUserId(),
                            emailHash,
                            requestIpHash,
                            userAgentHash,
                            AuthAttemptReasonCode.INVALID_CREDENTIALS
                    );
                    return new AuthenticationException("Invalid credentials");
                });

        byte[] candidateHash = serverAuthHashingService.hash(
                input.authSecret(),
                userAuth.getAuthSalt(),
                userAuth.getAuthHashParams()
        );

        if (!hashingService.constantTimeEquals(candidateHash, userAuth.getAuthHash())) {
            loginAntiAbuseService.recordFailure(
                    user.getUserId(),
                    emailHash,
                    requestIpHash,
                    userAgentHash,
                    AuthAttemptReasonCode.INVALID_CREDENTIALS
            );
            throw new AuthenticationException("Invalid credentials");
        }

        OffsetDateTime now = OffsetDateTime.now();
        OffsetDateTime refreshExpiresAt = now.plusDays(REFRESH_SESSION_TTL_DAYS);

        SessionTokenService.IssuedRefreshToken issuedRefreshToken =
                sessionTokenService.issueRefreshToken();

        UserSession userSession = UserSession.builder()
                .sessionId(UUID.randomUUID())
                .userId(user.getUserId())
                .refreshTokenHash(issuedRefreshToken.tokenHash())
                .deviceName(normalizeDeviceName(input.deviceName()))
                .userAgentHash(userAgentHash)
                .ipHash(requestIpHash)
                .createdAt(now)
                .expiresAt(refreshExpiresAt)
                .revokedAt(null)
                .lastSeenAt(now)
                .build();

        userSessionRepository.save(userSession);

        JwtTokenService.IssuedAccessToken issuedAccessToken =
                jwtTokenService.issueAccessToken(user, userSession.getSessionId());

        auditService.appendLoginSucceeded(user.getUserId(), now);

        return new AuthTokensResponse(
                userSession.getSessionId(),
                issuedAccessToken.tokenValue(),
                issuedAccessToken.expiresAt(),
                issuedRefreshToken.rawToken(),
                refreshExpiresAt.toInstant()
        );
    }

    private String normalizeDeviceName(String deviceName) {
        if (deviceName == null || deviceName.isBlank()) {
            return null;
        }
        return deviceName.trim();
    }

    @Transactional
    public AuthTokensResponse refreshSession(String refreshToken) {
        byte[] presentedTokenHash = sessionTokenService.hashPresentedRefreshToken(refreshToken);

        UserSession userSession = userSessionRepository
                .findByRefreshTokenHashAndRevokedAtIsNull(presentedTokenHash)
                .orElseThrow(() -> new AuthenticationException("Invalid refresh token"));

        OffsetDateTime now = OffsetDateTime.now();

        if (userSession.getExpiresAt().isBefore(now)) {
            userSession.setRevokedAt(now);
            userSessionRepository.save(userSession);
            throw new AuthenticationException("Refresh token expired");
        }

        User user = userRepository.findById(userSession.getUserId())
                .orElseThrow(() -> new AuthenticationException("Invalid session"));

        if (user.getStatus() != UserStatus.ACTIVE) {
            userSession.setRevokedAt(now);
            userSessionRepository.save(userSession);
            throw new AuthenticationException("Invalid session");
        }

        SessionTokenService.IssuedRefreshToken issuedRefreshToken =
                sessionTokenService.issueRefreshToken();

        OffsetDateTime newRefreshExpiresAt = now.plusDays(REFRESH_SESSION_TTL_DAYS);

        userSession.setRefreshTokenHash(issuedRefreshToken.tokenHash());
        userSession.setExpiresAt(newRefreshExpiresAt);
        userSession.setLastSeenAt(now);

        userSessionRepository.save(userSession);

        JwtTokenService.IssuedAccessToken issuedAccessToken =
                jwtTokenService.issueAccessToken(user, userSession.getSessionId());

        auditService.appendRefreshSucceeded(userSession.getUserId(), now);

        return new AuthTokensResponse(
                userSession.getSessionId(),
                issuedAccessToken.tokenValue(),
                issuedAccessToken.expiresAt(),
                issuedRefreshToken.rawToken(),
                newRefreshExpiresAt.toInstant()
        );
    }

    @Transactional
    public void logout(String refreshToken) {
        byte[] presentedTokenHash = sessionTokenService.hashPresentedRefreshToken(refreshToken);

        userSessionRepository.findByRefreshTokenHashAndRevokedAtIsNull(presentedTokenHash)
                .ifPresent(userSession -> {
                    OffsetDateTime now = OffsetDateTime.now();
                    userSession.setRevokedAt(now);
                    userSession.setLastSeenAt(now);
                    userSessionRepository.save(userSession);
                    auditService.appendLogoutSucceeded(userSession.getUserId(), now);
                });
    }

    @Transactional
    public void changePassword(UUID userId, ChangePasswordInput input) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new AuthenticationException("Invalid session"));

        if (user.getStatus() != UserStatus.ACTIVE) {
            throw new AuthenticationException("Invalid session");
        }

        UserAuth userAuth = userAuthRepository.findById(userId)
                .orElseThrow(() -> new AuthenticationException("Invalid session"));

        byte[] candidateHash = serverAuthHashingService.hash(
                input.currentAuthSecret(),
                userAuth.getAuthSalt(),
                userAuth.getAuthHashParams()
        );

        if (!hashingService.constantTimeEquals(candidateHash, userAuth.getAuthHash())) {
            throw new AuthenticationException("Не удалось подтвердить текущий мастер-пароль. Проверьте, что он введен верно.");
        }

        UserKeyMaterial userKeyMaterial = userKeyMaterialRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User key material not found"));

        OffsetDateTime now = OffsetDateTime.now();
        StoredAuthSecret storedAuthSecret = serverAuthHashingService.hashForStorage(input.newAuthSecret());

        userAuth.setAuthHash(storedAuthSecret.authHash());
        userAuth.setAuthSalt(storedAuthSecret.authSalt());
        userAuth.setAuthHashParams(storedAuthSecret.authHashParams());
        userAuth.setClientKdfParams(input.newClientKdfParams());
        userAuth.setPasswordChangedAt(now);
        userAuth.setUpdatedAt(now);

        userKeyMaterial.setWrappedAccountRootKey(input.newWrappedAccountRootKey());
        userKeyMaterial.setAccountRootWrapParams(input.newAccountRootWrapParams());

        userAuthRepository.save(userAuth);
        userKeyMaterialRepository.save(userKeyMaterial);
        userSessionRepository.revokeAllActiveSessionsByUserId(userId, now);

        auditService.appendPasswordChanged(userId, now);
    }

    @Transactional
    public void rotateUserKeys(UUID userId, RotateUserKeysInput input) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new AuthenticationException("Invalid session"));

        if (user.getStatus() != UserStatus.ACTIVE) {
            throw new AuthenticationException("Invalid session");
        }

        UserAuth userAuth = userAuthRepository.findById(userId)
                .orElseThrow(() -> new AuthenticationException("Invalid session"));

        byte[] candidateHash = serverAuthHashingService.hash(
                input.currentAuthSecret(),
                userAuth.getAuthSalt(),
                userAuth.getAuthHashParams()
        );

        if (!hashingService.constantTimeEquals(candidateHash, userAuth.getAuthHash())) {
            throw new AuthenticationException("РќРµ СѓРґР°Р»РѕСЃСЊ РїРѕРґС‚РІРµСЂРґРёС‚СЊ С‚РµРєСѓС‰РёР№ РјР°СЃС‚РµСЂ-РїР°СЂРѕР»СЊ. РџСЂРѕРІРµСЂСЊС‚Рµ, С‡С‚Рѕ РѕРЅ РІРІРµРґРµРЅ РІРµСЂРЅРѕ.");
        }

        UserKeyMaterial userKeyMaterial = userKeyMaterialRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User key material not found"));

        OffsetDateTime now = OffsetDateTime.now();
        List<VaultMember> activeMemberships = vaultMemberRepository.findByUserIdAndStatusesReadableAt(
                userId,
                List.of(VaultMemberStatus.ACTIVE),
                now
        );

        List<UUID> vaultIds = activeMemberships.stream()
                .map(membership -> membership.getId().getVaultId())
                .toList();

        List<VaultKeyEnvelope> currentActiveEnvelopes = vaultIds.isEmpty()
                ? List.of()
                : vaultKeyEnvelopeRepository.findCurrentActiveEnvelopesForRecipientAndVaultIds(
                userId,
                userKeyMaterial.getEncryptionKeyVersion(),
                vaultIds
        );

        validateRotateUserKeyInputs(activeMemberships, currentActiveEnvelopes, input.envelopes());

        Map<UUID, RotateUserKeysEnvelopeInput> envelopeInputsByVaultId = indexRotateEnvelopeInputs(input.envelopes());
        int previousEncryptionKeyVersion = userKeyMaterial.getEncryptionKeyVersion();
        int previousSigningKeyVersion = userKeyMaterial.getSigningKeyVersion();
        int newEncryptionKeyVersion = previousEncryptionKeyVersion + 1;
        int newSigningKeyVersion = previousSigningKeyVersion + 1;

        archiveCurrentKeyMaterial(userKeyMaterial, now);

        List<VaultKeyEnvelope> replacementEnvelopes = buildReplacementEnvelopes(
                userId,
                currentActiveEnvelopes,
                envelopeInputsByVaultId,
                newEncryptionKeyVersion,
                now
        );

        for (VaultKeyEnvelope envelope : currentActiveEnvelopes) {
            envelope.setRevokedAt(now);
        }

        userKeyMaterial.setPublicEncryptionKey(input.publicEncryptionKey());
        userKeyMaterial.setEncryptedPrivateEncryptionKey(input.encryptedPrivateEncryptionKey());
        userKeyMaterial.setEncryptionKeyParams(input.encryptionKeyParams());
        userKeyMaterial.setEncryptionKeyVersion(newEncryptionKeyVersion);

        userKeyMaterial.setPublicSigningKey(input.publicSigningKey());
        userKeyMaterial.setEncryptedPrivateSigningKey(input.encryptedPrivateSigningKey());
        userKeyMaterial.setSigningKeyParams(input.signingKeyParams());
        userKeyMaterial.setSigningKeyVersion(newSigningKeyVersion);
        userKeyMaterial.setRotatedAt(now);

        if (!currentActiveEnvelopes.isEmpty()) {
            vaultKeyEnvelopeRepository.saveAll(currentActiveEnvelopes);
        }
        if (!replacementEnvelopes.isEmpty()) {
            vaultKeyEnvelopeRepository.saveAll(replacementEnvelopes);
        }

        userKeyMaterialRepository.save(userKeyMaterial);
        userSessionRepository.revokeAllActiveSessionsByUserId(userId, now);

        for (VaultMember membership : activeMemberships) {
            vaultSyncService.appendTargetedMembershipChanged(
                    membership.getId().getVaultId(),
                    userId,
                    null,
                    userId,
                    now
            );
        }

        auditService.appendUserKeysRotated(
                userId,
                previousEncryptionKeyVersion,
                newEncryptionKeyVersion,
                previousSigningKeyVersion,
                newSigningKeyVersion,
                replacementEnvelopes.size(),
                now
        );
    }

    @Transactional
    public void deleteAccount(UUID userId, DeleteAccountInput input) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new AuthenticationException("Invalid session"));

        if (user.getStatus() != UserStatus.ACTIVE) {
            throw new AuthenticationException("Invalid session");
        }

        UserAuth userAuth = userAuthRepository.findById(userId)
                .orElseThrow(() -> new AuthenticationException("Invalid session"));

        byte[] candidateHash = serverAuthHashingService.hash(
                input.currentAuthSecret(),
                userAuth.getAuthSalt(),
                userAuth.getAuthHashParams()
        );

        if (!hashingService.constantTimeEquals(candidateHash, userAuth.getAuthHash())) {
            throw new AuthenticationException("Не удалось подтвердить текущий мастер-пароль. Проверьте, что он введен верно.");
        }

        OffsetDateTime now = OffsetDateTime.now();
        Set<UUID> soloOwnedVaultIds = resolveOwnedVaultsBeforeAccountDeletion(userId, now);

        revokeReadableMembershipsAndInvites(userId, now, soloOwnedVaultIds);
        deleteOwnedSoloVaults(soloOwnedVaultIds);

        userSessionRepository.revokeAllActiveSessionsByUserId(userId, now);
        userKeyMaterialRepository.deleteById(userId);
        userAuthRepository.deleteById(userId);

        user.setStatus(UserStatus.DELETED);
        user.setUpdatedAt(now);
        userRepository.save(user);

        auditService.appendAccountDeleted(userId, now);
    }

    @Transactional(readOnly = true)
    public UserKeyMaterial getCurrentUserKeyMaterial(UUID userId) {
        return userKeyMaterialRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User key material not found"));
    }

    @Transactional(readOnly = true)
    public PreloginResponse prelogin(PreloginRequest request, ClientRequestMetadata metadata) {
        preloginAntiAbuseService.checkAndRecord(
                hashingService.hashEmailForAbuse(request.email()),
                hashingService.hashRequestIp(metadata.clientIp()),
                hashingService.hashUserAgent(metadata.userAgent())
        );

        KdfParams clientKdfParams = userRepository.findByEmailIgnoreCaseAndStatusNot(request.email(), UserStatus.DELETED)
                .flatMap(user -> userAuthRepository.findById(user.getUserId()))
                .map(UserAuth::getClientKdfParams)
                .orElseGet(() -> buildDummyClientKdfParams(request.email()));

        return new PreloginResponse(
                kdfParamsResponseMapper.toResponse(clientKdfParams)
        );
    }

    private KdfParams buildDummyClientKdfParams(String email) {
        byte[] salt = deriveDummyPreloginSalt(email);

        return new KdfParams(
                DEFAULT_CLIENT_KDF_ALGORITHM,
                salt,
                DEFAULT_CLIENT_KDF_ITERATIONS,
                DEFAULT_CLIENT_KDF_MEMORY_KB,
                DEFAULT_CLIENT_KDF_PARALLELISM
        );
    }

    private byte[] deriveDummyPreloginSalt(String email) {
        String normalizedEmail = normalizeEmail(email);
        return ("password-manager:prelogin-dummy-salt:" + normalizedEmail)
                .getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }

    private String normalizeEmail(String email) {
        return email == null ? "" : email.trim().toLowerCase();
    }

    private Set<UUID> resolveOwnedVaultsBeforeAccountDeletion(UUID userId, OffsetDateTime now) {
        List<VaultMember> ownedMemberships = vaultMemberRepository.findByUserIdAndRoleAndStatusAndReadableAt(
                userId,
                VaultMemberRole.OWNER,
                VaultMemberStatus.ACTIVE,
                now
        );

        if (ownedMemberships.isEmpty()) {
            return Set.of();
        }

        List<UUID> blockingVaultIds = new java.util.ArrayList<>();
        Set<UUID> soloOwnedVaultIds = new java.util.LinkedHashSet<>();

        for (VaultMember membership : ownedMemberships) {
            UUID vaultId = membership.getId().getVaultId();

            if (hasOtherActiveMembers(vaultId, userId, now)) {
                blockingVaultIds.add(vaultId);
                continue;
            }

            soloOwnedVaultIds.add(vaultId);
        }

        if (!blockingVaultIds.isEmpty()) {
            String ownedVaultIds = blockingVaultIds.toString();

            throw new ConflictException(
                    "Нельзя удалить аккаунт, пока вы владеете сейфами, где есть другие активные участники. " +
                            "Сначала передайте владение таким сейфам. Оставшиеся owner-сейфы: " + ownedVaultIds
            );
        }

        return soloOwnedVaultIds;
    }

    private boolean hasOtherActiveMembers(UUID vaultId, UUID currentUserId, OffsetDateTime now) {
        return vaultMemberRepository.findByIdVaultIdOrderByJoinedAtAsc(vaultId).stream()
                .anyMatch(member ->
                        !member.getId().getUserId().equals(currentUserId) &&
                                member.getStatus() == VaultMemberStatus.ACTIVE &&
                                member.getRevokedAt() == null &&
                                (member.getExpiresAt() == null || member.getExpiresAt().isAfter(now))
                );
    }

    private void deleteOwnedSoloVaults(Set<UUID> vaultIds) {
        if (vaultIds.isEmpty()) {
            return;
        }

        for (UUID vaultId : vaultIds) {
            vaultRepository.findById(vaultId)
                    .ifPresent(vaultRepository::delete);
        }
    }

    private void revokeReadableMembershipsAndInvites(UUID userId, OffsetDateTime now, Set<UUID> ignoredVaultIds) {
        List<VaultMember> memberships = vaultMemberRepository.findByUserIdAndStatusesReadableAt(
                userId,
                List.of(VaultMemberStatus.ACTIVE, VaultMemberStatus.INVITED),
                now
        );
        memberships = memberships.stream()
                .filter(membership -> !ignoredVaultIds.contains(membership.getId().getVaultId()))
                .collect(Collectors.toList());

        List<VaultInvite> invites = vaultInviteRepository.findByInviteeUserIdOrderByCreatedAtDesc(userId);

        for (VaultMember membership : memberships) {
            UUID vaultId = membership.getId().getVaultId();
            VaultInvite pendingInvite = findPendingInvite(invites, vaultId);

            if (membership.getStatus() == VaultMemberStatus.INVITED) {
                if (pendingInvite != null && pendingInvite.getStatus() == VaultInviteStatus.PENDING) {
                    pendingInvite.setStatus(VaultInviteStatus.DECLINED);
                    pendingInvite.setRevokedAt(now);
                    vaultInviteRepository.save(pendingInvite);
                    auditService.appendInviteDeclined(userId, vaultId, pendingInvite.getInviteId(), now);
                }

                membership.setStatus(VaultMemberStatus.REVOKED);
                membership.setRevokedAt(now);
                vaultMemberRepository.save(membership);
                revokeActiveEnvelopes(vaultId, userId, now);
                vaultSyncService.appendTargetedMembershipChanged(
                        vaultId,
                        userId,
                        pendingInvite != null ? pendingInvite.getInviteId() : null,
                        userId,
                        now
                );
                continue;
            }

            membership.setStatus(VaultMemberStatus.REVOKED);
            membership.setRevokedAt(now);
            vaultMemberRepository.save(membership);
            revokeActiveEnvelopes(vaultId, userId, now);
            vaultSyncService.appendTargetedMembershipChanged(
                    vaultId,
                    userId,
                    pendingInvite != null ? pendingInvite.getInviteId() : null,
                    userId,
                    now
            );
            auditService.appendMemberRevoked(userId, vaultId, userId, now);
        }
    }

    private VaultInvite findPendingInvite(List<VaultInvite> invites, UUID vaultId) {
        return invites.stream()
                .filter(invite -> invite.getVaultId().equals(vaultId))
                .filter(invite -> invite.getStatus() == VaultInviteStatus.PENDING)
                .findFirst()
                .orElse(null);
    }

    private void revokeActiveEnvelopes(UUID vaultId, UUID recipientUserId, OffsetDateTime now) {
        List<VaultKeyEnvelope> envelopes = vaultKeyEnvelopeRepository.findActiveEnvelopes(
                vaultId,
                recipientUserId
        );

        for (VaultKeyEnvelope envelope : envelopes) {
            envelope.setRevokedAt(now);
        }

        if (!envelopes.isEmpty()) {
            vaultKeyEnvelopeRepository.saveAll(envelopes);
        }
    }

    private void validateRotateUserKeyInputs(
            List<VaultMember> activeMemberships,
            List<VaultKeyEnvelope> currentActiveEnvelopes,
            List<RotateUserKeysEnvelopeInput> envelopeInputs
    ) {
        if (activeMemberships.size() != currentActiveEnvelopes.size()) {
            throw new ConflictException(
                    "РќРµ СѓРґР°Р»РѕСЃСЊ РїРµСЂРµРІС‹РїСѓСЃС‚РёС‚СЊ РєР»СЋС‡Рё: РЅРµ РЅР°Р№РґРµРЅС‹ Р°РєС‚РёРІРЅС‹Рµ envelope-Р·Р°РїРёСЃРё РґР»СЏ РІСЃРµС… РґРѕСЃС‚СѓРїРЅС‹С… СЃРµР№С„РѕРІ."
            );
        }

        Map<UUID, RotateUserKeysEnvelopeInput> indexed = indexRotateEnvelopeInputs(envelopeInputs);
        if (indexed.size() != currentActiveEnvelopes.size()) {
            throw new InvalidRequestException(
                    "Rotate request must contain exactly one replacement envelope for each ACTIVE vault"
            );
        }

        for (VaultKeyEnvelope currentEnvelope : currentActiveEnvelopes) {
            if (!indexed.containsKey(currentEnvelope.getVaultId())) {
                throw new InvalidRequestException(
                        "Missing replacement envelope for vault " + currentEnvelope.getVaultId()
                );
            }
        }
    }

    private Map<UUID, RotateUserKeysEnvelopeInput> indexRotateEnvelopeInputs(
            List<RotateUserKeysEnvelopeInput> envelopeInputs
    ) {
        Map<UUID, RotateUserKeysEnvelopeInput> indexed = new LinkedHashMap<>();

        for (RotateUserKeysEnvelopeInput envelopeInput : envelopeInputs) {
            RotateUserKeysEnvelopeInput previous = indexed.put(envelopeInput.vaultId(), envelopeInput);
            if (previous != null) {
                throw new InvalidRequestException(
                        "Duplicate replacement envelope for vault " + envelopeInput.vaultId()
                );
            }
        }

        return indexed;
    }

    private List<VaultKeyEnvelope> buildReplacementEnvelopes(
            UUID userId,
            List<VaultKeyEnvelope> currentActiveEnvelopes,
            Map<UUID, RotateUserKeysEnvelopeInput> envelopeInputsByVaultId,
            int newEncryptionKeyVersion,
            OffsetDateTime now
    ) {
        return currentActiveEnvelopes.stream()
                .map(currentEnvelope -> {
                    RotateUserKeysEnvelopeInput envelopeInput =
                            envelopeInputsByVaultId.get(currentEnvelope.getVaultId());

                    return VaultKeyEnvelope.builder()
                            .envelopeId(UUID.randomUUID())
                            .vaultId(currentEnvelope.getVaultId())
                            .vaultKeyVersion(currentEnvelope.getVaultKeyVersion())
                            .recipientUserId(userId)
                            .recipientEncryptionKeyVersion(newEncryptionKeyVersion)
                            .envelopeVersion(CURRENT_ENVELOPE_VERSION)
                            .encryptedVaultKey(envelopeInput.encryptedVaultKey())
                            .envelopeParams(envelopeInput.envelopeParams())
                            .createdByUserId(userId)
                            .createdAt(now)
                            .build();
                })
                .toList();
    }

    private void archiveCurrentKeyMaterial(UserKeyMaterial userKeyMaterial, OffsetDateTime now) {
        UserKeyMaterialHistory history = UserKeyMaterialHistory.builder()
                .historyId(UUID.randomUUID())
                .userId(userKeyMaterial.getUserId())
                .wrappedAccountRootKey(userKeyMaterial.getWrappedAccountRootKey())
                .accountRootWrapParams(userKeyMaterial.getAccountRootWrapParams())
                .accountRootVersion(userKeyMaterial.getAccountRootVersion())
                .publicEncryptionKey(userKeyMaterial.getPublicEncryptionKey())
                .encryptedPrivateEncryptionKey(userKeyMaterial.getEncryptedPrivateEncryptionKey())
                .encryptionKeyParams(userKeyMaterial.getEncryptionKeyParams())
                .encryptionKeyVersion(userKeyMaterial.getEncryptionKeyVersion())
                .publicSigningKey(userKeyMaterial.getPublicSigningKey())
                .encryptedPrivateSigningKey(userKeyMaterial.getEncryptedPrivateSigningKey())
                .signingKeyParams(userKeyMaterial.getSigningKeyParams())
                .signingKeyVersion(userKeyMaterial.getSigningKeyVersion())
                .createdAt(userKeyMaterial.getCreatedAt())
                .rotatedAt(userKeyMaterial.getRotatedAt())
                .archivedAt(now)
                .build();

        userKeyMaterialHistoryRepository.save(history);
    }
}
