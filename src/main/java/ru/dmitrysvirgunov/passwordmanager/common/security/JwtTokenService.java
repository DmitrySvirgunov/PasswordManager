package ru.dmitrysvirgunov.passwordmanager.common.security;

import com.nimbusds.jose.jwk.source.ImmutableSecret;
import lombok.Getter;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Service;
import ru.dmitrysvirgunov.passwordmanager.auth.entity.User;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.UUID;

@Service
public class JwtTokenService {

    private final JwtTokenProperties properties;
    private final JwtEncoder jwtEncoder;

    public JwtTokenService(JwtTokenProperties properties) {
        this.properties = properties;

        byte[] secretBytes;
        try {
            secretBytes = Base64.getDecoder().decode(properties.secretBase64());
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("JWT secretBase64 is not valid Base64", e);
        }

        if (secretBytes.length < 32) {
            throw new IllegalStateException("JWT HMAC secret must be at least 32 bytes");
        }

        SecretKey secretKey = new SecretKeySpec(secretBytes, "HmacSHA256");
        this.jwtEncoder = new NimbusJwtEncoder(new ImmutableSecret<>(secretKey));
    }

    public IssuedAccessToken issueAccessToken(User user, UUID sessionId) {
        Instant now = Instant.now();
        Instant expiresAt = now.plus(properties.accessTtlMinutes(), ChronoUnit.MINUTES);

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(properties.issuer())
                .subject(user.getUserId().toString())
                .issuedAt(now)
                .expiresAt(expiresAt)
                .claim("email", user.getEmail())
                .claim("sid", sessionId.toString())
                .build();

        JwsHeader header = JwsHeader.with(MacAlgorithm.HS256)
                .type("JWT")
                .build();

        String tokenValue = jwtEncoder.encode(JwtEncoderParameters.from(header, claims))
                .getTokenValue();

        return new IssuedAccessToken(tokenValue, expiresAt);
    }

    public record IssuedAccessToken(
            String tokenValue,
            Instant expiresAt
    ) {
    }
}