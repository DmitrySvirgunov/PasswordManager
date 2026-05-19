package ru.dmitrysvirgunov.passwordmanager.common.security;

import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

@Service
@RequiredArgsConstructor
public class HashingService {

    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final String SHA_256_ALGORITHM = "SHA-256";
    private static final int MIN_SECRET_BYTES = 32;

    private final HashingProperties hashingProperties;

    private SecretKeySpec secretKeySpec;

    @PostConstruct
    void init() {
        String secretBase64 = requireConfiguredValue(
                hashingProperties.hmacSecretBase64(),
                "security.hashing.hmac-secret-base64"
        );

        final byte[] secret;
        try {
            secret = Base64.getDecoder().decode(secretBase64);
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("Invalid Base64 in security.hashing.hmac-secret-base64", e);
        }

        if (secret.length < MIN_SECRET_BYTES) {
            throw new IllegalStateException("HMAC secret must be at least 32 bytes");
        }

        this.secretKeySpec = new SecretKeySpec(secret, HMAC_ALGORITHM);
    }

    public byte[] hashVerificationToken(String rawToken) {
        if (rawToken == null || rawToken.isBlank()) {
            throw new IllegalArgumentException("rawToken must not be blank");
        }

        try {
            MessageDigest digest = MessageDigest.getInstance(SHA_256_ALGORITHM);
            return digest.digest(rawToken.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 algorithm is not available", e);
        }
    }

    public byte[] hashRequestIp(String ip) {
        if (ip == null || ip.isBlank()) {
            return null;
        }
        return hmacSha256(normalizeIp(ip));
    }

    public byte[] hashUserAgent(String userAgent) {
        if (userAgent == null || userAgent.isBlank()) {
            return null;
        }
        return hmacSha256(userAgent.trim());
    }

    public byte[] hashEmailForAbuse(String email) {
        if (email == null || email.isBlank()) {
            throw new IllegalArgumentException("email must not be blank");
        }
        return hmacSha256(normalizeEmail(email));
    }

    public boolean constantTimeEquals(byte[] left, byte[] right) {
        return MessageDigest.isEqual(left, right);
    }

    private byte[] hmacSha256(String value) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(secretKeySpec);
            return mac.doFinal(value.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("HmacSHA256 algorithm is not available", e);
        } catch (InvalidKeyException e) {
            throw new IllegalStateException("Invalid HMAC secret key", e);
        }
    }

    private String normalizeIp(String ip) {
        String trimmed = ip.trim();
        try {
            return InetAddress.getByName(trimmed).getHostAddress();
        } catch (UnknownHostException e) {
            return trimmed;
        }
    }

    private String requireConfiguredValue(String value, String fieldName) {
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(fieldName + " must be configured");
        }
        return value.trim();
    }

    private String requireNotBlank(String value, String fieldName) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(fieldName + " must not be blank");
        }
        return value.trim();
    }

    private String normalizeEmail(String email) {
        return email.trim().toLowerCase();
    }
}
