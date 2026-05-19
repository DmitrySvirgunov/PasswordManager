package ru.dmitrysvirgunov.passwordmanager.vault.mapper;

import org.springframework.stereotype.Component;
import ru.dmitrysvirgunov.passwordmanager.common.exception.InvalidRequestException;
import ru.dmitrysvirgunov.passwordmanager.vault.model.UploadVaultBlobPartInput;

import java.util.Base64;

@Component
public class UploadVaultBlobPartRequestMapper {

    public UploadVaultBlobPartInput toInput(byte[] ciphertextChunk, String ciphertextChunkSha256Base64) {
        if (ciphertextChunk == null || ciphertextChunk.length == 0) {
            throw new InvalidRequestException("ciphertextChunk is required");
        }

        if (ciphertextChunkSha256Base64 == null || ciphertextChunkSha256Base64.isBlank()) {
            throw new InvalidRequestException("ciphertextChunkSha256 header is required");
        }

        return new UploadVaultBlobPartInput(
                ciphertextChunk,
                decodeBase64(ciphertextChunkSha256Base64)
        );
    }

    private byte[] decodeBase64(String value) {
        try {
            return Base64.getDecoder().decode(value);
        } catch (IllegalArgumentException e) {
            throw new InvalidRequestException("Invalid Base64 value", e);
        }
    }
}
