package ru.dmitrysvirgunov.passwordmanager.auth.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;
import ru.dmitrysvirgunov.passwordmanager.auth.dto.request.*;
import ru.dmitrysvirgunov.passwordmanager.auth.dto.response.AuthTokensResponse;
import ru.dmitrysvirgunov.passwordmanager.auth.dto.response.CurrentUserResponse;
import ru.dmitrysvirgunov.passwordmanager.auth.dto.response.RegisterResponse;
import ru.dmitrysvirgunov.passwordmanager.auth.dto.response.VerifyEmailResponse;
import ru.dmitrysvirgunov.passwordmanager.auth.mapper.LoginRequestMapper;
import ru.dmitrysvirgunov.passwordmanager.auth.mapper.RegisterRequestMapper;
import ru.dmitrysvirgunov.passwordmanager.auth.model.LoginInput;
import ru.dmitrysvirgunov.passwordmanager.auth.model.RegisterInput;
import ru.dmitrysvirgunov.passwordmanager.auth.model.RegistrationRequestMetadata;
import ru.dmitrysvirgunov.passwordmanager.auth.service.AuthService;
import ru.dmitrysvirgunov.passwordmanager.common.web.ClientRequestMetadataResolver;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final RegisterRequestMapper registerRequestMapper;
    private final ClientRequestMetadataResolver clientRequestMetadataResolver;
    private final LoginRequestMapper loginRequestMapper;

    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    public RegisterResponse register(
            @Valid @RequestBody RegisterRequest request,
            HttpServletRequest httpServletRequest
    ) {
        RegisterInput input = registerRequestMapper.toInput(request);
        RegistrationRequestMetadata metadata = clientRequestMetadataResolver.resolve(httpServletRequest);

        return authService.register(input, metadata);
    }

    @PostMapping("/verify-email")
    @ResponseStatus(HttpStatus.OK)
    public VerifyEmailResponse verifyEmail(@Valid @RequestBody VerifyEmailRequest request) {
        return authService.verifyEmail(request.token());
    }

    @PostMapping("/login")
    @ResponseStatus(HttpStatus.OK)
    public AuthTokensResponse login(
            @Valid @RequestBody LoginRequest request,
            HttpServletRequest httpServletRequest
    ) {
        LoginInput input = loginRequestMapper.toInput(request);
        RegistrationRequestMetadata metadata = clientRequestMetadataResolver.resolve(httpServletRequest);

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
}