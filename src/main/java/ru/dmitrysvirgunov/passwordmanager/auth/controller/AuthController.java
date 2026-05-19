package ru.dmitrysvirgunov.passwordmanager.auth.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;
import ru.dmitrysvirgunov.passwordmanager.auth.dto.request.*;
import ru.dmitrysvirgunov.passwordmanager.auth.dto.response.*;
import ru.dmitrysvirgunov.passwordmanager.auth.entity.UserKeyMaterial;
import ru.dmitrysvirgunov.passwordmanager.auth.mapper.AuthResponseMapper;
import ru.dmitrysvirgunov.passwordmanager.auth.mapper.ChangePasswordRequestMapper;
import ru.dmitrysvirgunov.passwordmanager.auth.mapper.DeleteAccountRequestMapper;
import ru.dmitrysvirgunov.passwordmanager.auth.mapper.LoginRequestMapper;
import ru.dmitrysvirgunov.passwordmanager.auth.mapper.RegisterRequestMapper;
import ru.dmitrysvirgunov.passwordmanager.auth.mapper.RotateUserKeysRequestMapper;
import ru.dmitrysvirgunov.passwordmanager.auth.model.ChangePasswordInput;
import ru.dmitrysvirgunov.passwordmanager.auth.model.DeleteAccountInput;
import ru.dmitrysvirgunov.passwordmanager.auth.model.LoginInput;
import ru.dmitrysvirgunov.passwordmanager.auth.model.RegisterInput;
import ru.dmitrysvirgunov.passwordmanager.auth.model.RotateUserKeysInput;
import ru.dmitrysvirgunov.passwordmanager.common.web.ClientRequestMetadata;
import ru.dmitrysvirgunov.passwordmanager.auth.service.AuthService;
import ru.dmitrysvirgunov.passwordmanager.common.web.ClientRequestMetadataResolver;

import java.util.UUID;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final RegisterRequestMapper registerRequestMapper;
    private final ClientRequestMetadataResolver clientRequestMetadataResolver;
    private final LoginRequestMapper loginRequestMapper;
    private final ChangePasswordRequestMapper changePasswordRequestMapper;
    private final DeleteAccountRequestMapper deleteAccountRequestMapper;
    private final RotateUserKeysRequestMapper rotateUserKeysRequestMapper;
    private final AuthResponseMapper authResponseMapper;

    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    public RegisterResponse register(
            @Valid @RequestBody RegisterRequest request,
            HttpServletRequest httpServletRequest
    ) {
        RegisterInput input = registerRequestMapper.toInput(request);
        ClientRequestMetadata metadata = clientRequestMetadataResolver.resolve(httpServletRequest);

        return authService.register(input, metadata);
    }

    @PostMapping("/verify-email")
    @ResponseStatus(HttpStatus.OK)
    public VerifyEmailResponse verifyEmail(
            @Valid @RequestBody VerifyEmailRequest request,
            HttpServletRequest httpServletRequest
    ) {
        return authService.verifyEmail(
                request.token(),
                clientRequestMetadataResolver.resolve(httpServletRequest)
        );
    }

    @PostMapping("/login")
    @ResponseStatus(HttpStatus.OK)
    public AuthTokensResponse login(
            @Valid @RequestBody LoginRequest request,
            HttpServletRequest httpServletRequest
    ) {
        LoginInput input = loginRequestMapper.toInput(request);
        ClientRequestMetadata metadata = clientRequestMetadataResolver.resolve(httpServletRequest);

        return authService.login(input, metadata);
    }

    @PostMapping("/refresh")
    @ResponseStatus(HttpStatus.OK)
    public AuthTokensResponse refresh(@Valid @RequestBody RefreshTokenRequest request) {
        return authService.refreshSession(request.refreshToken());
    }

    @PostMapping("/logout")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void logout(@Valid @RequestBody LogoutRequest request) {
        authService.logout(request.refreshToken());
    }

    @GetMapping("/me")
    @ResponseStatus(HttpStatus.OK)
    public CurrentUserResponse me(@AuthenticationPrincipal Jwt jwt) {
        return new CurrentUserResponse(
                jwt.getSubject(),
                jwt.getClaimAsString("email"),
                jwt.getClaimAsString("sid"),
                jwt.getIssuer() != null ? jwt.getIssuer().toString() : null
        );
    }

    @GetMapping("/key-material")
    @ResponseStatus(HttpStatus.OK)
    public CurrentUserKeyMaterialResponse keyMaterial(@AuthenticationPrincipal Jwt jwt) {
        UUID userId = UUID.fromString(jwt.getSubject());
        UserKeyMaterial keyMaterial = authService.getCurrentUserKeyMaterial(userId);
        return authResponseMapper.toCurrentUserKeyMaterialResponse(keyMaterial);
    }

    @PostMapping("/prelogin")
    public ResponseEntity<PreloginResponse> prelogin(
            @Valid @RequestBody PreloginRequest request,
            HttpServletRequest httpServletRequest
    ) {
        return ResponseEntity.ok(
                authService.prelogin(
                        request,
                        clientRequestMetadataResolver.resolve(httpServletRequest)
                )
        );
    }

    @PostMapping("/change-password")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void changePassword(
            @Valid @RequestBody ChangePasswordRequest request,
            @AuthenticationPrincipal Jwt jwt
    ) {
        ChangePasswordInput input = changePasswordRequestMapper.toInput(request);
        authService.changePassword(UUID.fromString(jwt.getSubject()), input);
    }

    @PostMapping("/rotate-keys")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void rotateKeys(
            @Valid @RequestBody RotateUserKeysRequest request,
            @AuthenticationPrincipal Jwt jwt
    ) {
        RotateUserKeysInput input = rotateUserKeysRequestMapper.toInput(request);
        authService.rotateUserKeys(UUID.fromString(jwt.getSubject()), input);
    }

    @PostMapping("/delete-account")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void deleteAccount(
            @Valid @RequestBody DeleteAccountRequest request,
            @AuthenticationPrincipal Jwt jwt
    ) {
        DeleteAccountInput input = deleteAccountRequestMapper.toInput(request);
        authService.deleteAccount(UUID.fromString(jwt.getSubject()), input);
    }
}
