package ru.dmitrysvirgunov.passwordmanager.audit.service;

import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import ru.dmitrysvirgunov.passwordmanager.audit.config.AuditSigningProperties;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class AuditVerificationKeyService {

    private final AuditSigningProperties properties;

    private final Map<String, PublicKey> publicKeysByKeyId = new HashMap<>();

    @PostConstruct
    void init() {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("Ed25519");

            if (properties.getKeyId() != null
                    && !properties.getKeyId().isBlank()
                    && properties.getPublicKeyX509Base64() != null
                    && !properties.getPublicKeyX509Base64().isBlank()) {
                publicKeysByKeyId.put(
                        properties.getKeyId(),
                        decodePublicKey(keyFactory, properties.getPublicKeyX509Base64())
                );
            }

            for (AuditSigningProperties.TrustedPublicKey trusted : properties.getTrustedPublicKeys()) {
                if (trusted.getKeyId() == null || trusted.getKeyId().isBlank()) {
                    throw new IllegalStateException("Audit trusted public key keyId is not configured");
                }
                if (trusted.getPublicKeyX509Base64() == null || trusted.getPublicKeyX509Base64().isBlank()) {
                    throw new IllegalStateException("Audit trusted public key material is not configured");
                }

                publicKeysByKeyId.put(
                        trusted.getKeyId(),
                        decodePublicKey(keyFactory, trusted.getPublicKeyX509Base64())
                );
            }
        } catch (Exception e) {
            throw new IllegalStateException("Failed to initialize audit verification keys", e);
        }
    }

    public boolean verify(String keyId, byte[] payload, byte[] signatureBytes) {
        try {
            PublicKey publicKey = publicKeysByKeyId.get(keyId);
            if (publicKey == null) {
                return false;
            }

            Signature signature = Signature.getInstance("Ed25519");
            signature.initVerify(publicKey);
            signature.update(payload);
            try {
                return signature.verify(signatureBytes);
            } catch (SignatureException | IllegalArgumentException e) {
                return false;
            }
        } catch (Exception e) {
            throw new IllegalStateException("Failed to verify audit signature", e);
        }
    }

    private PublicKey decodePublicKey(KeyFactory keyFactory, String publicKeyX509Base64) throws Exception {
        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyX509Base64);
        return keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
    }
}
