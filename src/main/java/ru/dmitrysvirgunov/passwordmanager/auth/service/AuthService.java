package ru.dmitrysvirgunov.passwordmanager.auth.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.dmitrysvirgunov.passwordmanager.auth.dto.response.*;
import ru.dmitrysvirgunov.passwordmanager.auth.entity.*;
import ru.dmitrysvirgunov.passwordmanager.auth.event.RegistrationVerificationEmailRequestedEvent;
import ru.dmitrysvirgunov.passwordmanager.auth.model.*;
import ru.dmitrysvirgunov.passwordmanager.auth.repository.*;
import ru.dmitrysvirgunov.passwordmanager.common.exception.AuthenticationException;
import ru.dmitrysvirgunov.passwordmanager.common.exception.ResourceAlreadyExistsException;
import ru.dmitrysvirgunov.passwordmanager.common.exception.TokenExpiredException;
import ru.dmitrysvirgunov.passwordmanager.common.exception.TokenInvalidException;
import ru.dmitrysvirgunov.passwordmanager.common.security.HashingService;
import ru.dmitrysvirgunov.passwordmanager.common.security.JwtTokenService;
import ru.dmitrysvirgunov.passwordmanager.common.security.ServerAuthHashingService;
import ru.dmitrysvirgunov.passwordmanager.common.security.ServerAuthHashingService.StoredAuthSecret;
import ru.dmitrysvirgunov.passwordmanager.config.RegistrationProperties;

import java.time.OffsetDateTime;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private static final long REGISTRATION_TOKEN_TTL_MINUTES = 30;
    private static final int CURRENT_AUTH_VERSION = 2;
    private static final int CURRENT_KEY_VERSION = 1;
    private static final long REFRESH_SESSION_TTL_DAYS = 30;

    private final UserRepository userRepository;
    private final PendingRegistrationRepository pendingRegistrationRepository;
    private final VerificationTokenService verificationTokenService;
    private final HashingService hashingService;
    private final ServerAuthHashingService serverAuthHashingService;
    private final RegistrationAntiAbuseService registrationAntiAbuseService;
    private final UserAuthRepository userAuthRepository;
    private final UserKeyMaterialRepository userKeyMaterialRepository;
    private final ApplicationEventPublisher eventPublisher;
    private final RegistrationProperties registrationProperties;
    private final UserSessionRepository userSessionRepository;
    private final SessionTokenService sessionTokenService;
    private final JwtTokenService jwtTokenService;

    @Transactional
    public RegisterResponse register(RegisterInput registerInput, RegistrationRequestMetadata metadata) {
        log.info("registration mode={}", registrationProperties.mode());
        return switch (registrationProperties.mode()) {
            case AUTO_ACTIVATE -> registerAndActivateImmediately(registerInput, metadata);
            case EMAIL_VERIFICATION -> registerWithPendingVerification(registerInput, metadata);
        };
    }

    private RegisterResponse registerWithPendingVerification(
            RegisterInput registerInput,
            RegistrationRequestMetadata metadata
    ) {
        OffsetDateTime now = OffsetDateTime.now();
        OffsetDateTime expiresAt = now.plusMinutes(REGISTRATION_TOKEN_TTL_MINUTES);

        String rawToken = verificationTokenService.generateRawToken();
        byte[] tokenHash = hashingService.hashVerificationToken(rawToken);
        StoredAuthSecret storedAuthSecret = serverAuthHashingService.hashForStorage(registerInput.authSecret());

        RegistrationHashes hashes = checkRegistrationAntiAbuse(registerInput, metadata);

        if (userRepository.existsByEmailIgnoreCase(registerInput.email())) {
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
            RegistrationRequestMetadata metadata
    ) {
        if (userRepository.existsByEmailIgnoreCase(registerInput.email())) {
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
                registerInput.publicKey(),
                registerInput.encryptedPrivateKey(),
                registerInput.keyParams(),
                now
        );

        try {
            userRepository.saveAndFlush(user);
        } catch (DataIntegrityViolationException ex) {
            throw new ResourceAlreadyExistsException("User with this email already exists");
        }

        userAuthRepository.save(userAuth);
        userKeyMaterialRepository.save(userKeyMaterial);

        return new RegisterResponse(
                registerInput.email(),
                RegistrationStatus.ACTIVE
        );
    }

    @Transactional
    public VerifyEmailResponse verifyEmail(String rawToken) {
        OffsetDateTime now = OffsetDateTime.now();
        byte[] tokenHash = hashingService.hashVerificationToken(rawToken);

        PendingRegistration pendingRegistration = pendingRegistrationRepository
                .findByTokenHashAndUsedAtIsNull(tokenHash)
                .orElseThrow(() -> new TokenInvalidException("Verification token is invalid"));

        if (!pendingRegistration.getExpiresAt().isAfter(now)) {
            throw new TokenExpiredException("Verification token has expired");
        }

        if (userRepository.existsByEmailIgnoreCase(pendingRegistration.getEmail())) {
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
                pendingRegistration.getPublicKey(),
                pendingRegistration.getEncryptedPrivateKey(),
                pendingRegistration.getKeyParams(),
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
        target.setPublicKey(input.publicKey());
        target.setEncryptedPrivateKey(input.encryptedPrivateKey());
        target.setKeyParams(input.keyParams());
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
            byte[] publicKey,
            byte[] encryptedPrivateKey,
            KeyParams keyParams,
            OffsetDateTime now
    ) {
        return UserKeyMaterial.builder()
                .userId(userId)
                .publicKey(publicKey)
                .encryptedPrivateKey(encryptedPrivateKey)
                .keyParams(keyParams)
                .keyVersion(CURRENT_KEY_VERSION)
                .createdAt(now)
                .rotatedAt(null)
                .build();
    }

    private RegistrationHashes checkRegistrationAntiAbuse(
            RegisterInput input,
            RegistrationRequestMetadata metadata
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
    public AuthTokensResponse login(LoginInput input, RegistrationRequestMetadata metadata) {
        User user = userRepository.findByEmailIgnoreCase(input.email())
                .orElseThrow(() -> new AuthenticationException("Invalid credentials"));

        if (user.getStatus() != UserStatus.ACTIVE) {
            throw new AuthenticationException("Invalid credentials");
        }

        UserAuth userAuth = userAuthRepository.findById(user.getUserId())
                .orElseThrow(() -> new AuthenticationException("Invalid credentials"));

        byte[] candidateHash = serverAuthHashingService.hash(
                input.authSecret(),
                userAuth.getAuthSalt(),
                userAuth.getAuthHashParams()
        );

        if (!hashingService.constantTimeEquals(candidateHash, userAuth.getAuthHash())) {
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
                .userAgentHash(hashingService.hashUserAgent(metadata.userAgent()))
                .ipHash(hashingService.hashRequestIp(metadata.clientIp()))
                .createdAt(now)
                .expiresAt(refreshExpiresAt)
                .revokedAt(null)
                .lastSeenAt(now)
                .build();

        userSessionRepository.save(userSession);

        JwtTokenService.IssuedAccessToken issuedAccessToken =
                jwtTokenService.issueAccessToken(user, userSession.getSessionId());

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
                });
    }
}
