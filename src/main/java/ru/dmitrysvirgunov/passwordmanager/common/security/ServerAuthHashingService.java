package ru.dmitrysvirgunov.passwordmanager.common.security;

import lombok.RequiredArgsConstructor;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.springframework.stereotype.Service;
import ru.dmitrysvirgunov.passwordmanager.auth.model.AuthHashParams;

import java.security.SecureRandom;
import java.util.Locale;

@Service
@RequiredArgsConstructor
public class ServerAuthHashingService {

    private static final String ARGON_2_ID = "argon2id";

    private final AuthHashingProperties properties;
    private final SecureRandom secureRandom = new SecureRandom();

    public StoredAuthSecret hashForStorage(byte[] authSecret) {
        validateAuthSecret(authSecret);

        byte[] salt = new byte[properties.saltLengthBytes()];
        secureRandom.nextBytes(salt);

        AuthHashParams params = currentParams();
        byte[] authHash = hash(authSecret, salt, params);

        return new StoredAuthSecret(authHash, salt, params);
    }

    public byte[] hash(byte[] authSecret, byte[] salt, AuthHashParams params) {
        validateAuthSecret(authSecret);
        validateSalt(salt);
        validateParams(params);

        Argon2Parameters.Builder builder = new Argon2Parameters.Builder(resolveArgonType(params.algorithm()))
                .withSalt(salt)
                .withIterations(params.iterations())
                .withMemoryAsKB(params.memoryKb())
                .withParallelism(params.parallelism());

        Argon2BytesGenerator generator = new Argon2BytesGenerator();
        generator.init(builder.build());

        byte[] hash = new byte[params.hashLengthBytes()];
        generator.generateBytes(authSecret, hash, 0, hash.length);
        return hash;
    }

    public AuthHashParams currentParams() {
        AuthHashParams params = new AuthHashParams(
                normalizedAlgorithm(properties.algorithm()),
                properties.iterations(),
                properties.memoryKb(),
                properties.parallelism(),
                properties.hashLengthBytes()
        );
        validateParams(params);
        return params;
    }

    private int resolveArgonType(String algorithm) {
        return switch (normalizedAlgorithm(algorithm)) {
            case ARGON_2_ID -> Argon2Parameters.ARGON2_id;
            default -> throw new IllegalArgumentException("Unsupported auth hash algorithm: " + algorithm);
        };
    }

    private String normalizedAlgorithm(String algorithm) {
        if (algorithm == null || algorithm.isBlank()) {
            throw new IllegalArgumentException("auth hash algorithm must not be blank");
        }
        return algorithm.trim().toLowerCase(Locale.ROOT);
    }

    private void validateAuthSecret(byte[] authSecret) {
        if (authSecret == null || authSecret.length == 0) {
            throw new IllegalArgumentException("authSecret must not be empty");
        }
    }

    private void validateSalt(byte[] salt) {
        if (salt == null || salt.length == 0) {
            throw new IllegalArgumentException("auth hash salt must not be empty");
        }
    }

    private void validateParams(AuthHashParams params) {
        if (params.iterations() < 1) {
            throw new IllegalArgumentException("auth hash iterations must be >= 1");
        }
        if (params.memoryKb() < 1) {
            throw new IllegalArgumentException("auth hash memoryKb must be >= 1");
        }
        if (params.parallelism() < 1) {
            throw new IllegalArgumentException("auth hash parallelism must be >= 1");
        }
        if (params.hashLengthBytes() < 16) {
            throw new IllegalArgumentException("auth hash length must be >= 16 bytes");
        }
    }

    public record StoredAuthSecret(
            byte[] authHash,
            byte[] authSalt,
            AuthHashParams authHashParams
    ) {
    }
}
