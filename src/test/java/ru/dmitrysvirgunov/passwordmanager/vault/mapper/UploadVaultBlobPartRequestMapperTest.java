package ru.dmitrysvirgunov.passwordmanager.vault.mapper;

import org.junit.jupiter.api.Test;
import ru.dmitrysvirgunov.passwordmanager.common.exception.InvalidRequestException;
import ru.dmitrysvirgunov.passwordmanager.vault.model.UploadVaultBlobPartInput;

import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class UploadVaultBlobPartRequestMapperTest {

    private final UploadVaultBlobPartRequestMapper mapper = new UploadVaultBlobPartRequestMapper();

    @Test
    void shouldBuildInputFromRawChunkAndHashHeader() {
        byte[] chunk = new byte[]{1, 2, 3};
        byte[] chunkSha256 = new byte[]{4, 5, 6};
        String chunkSha256Base64 = Base64.getEncoder().encodeToString(chunkSha256);

        UploadVaultBlobPartInput input = mapper.toInput(chunk, chunkSha256Base64);

        assertThat(input.ciphertextChunk()).isSameAs(chunk);
        assertThat(input.ciphertextChunkSha256()).containsExactly(chunkSha256);
    }

    @Test
    void shouldRejectMissingChunk() {
        assertThatThrownBy(() -> mapper.toInput(new byte[0], "BAUG"))
                .isInstanceOf(InvalidRequestException.class)
                .hasMessage("ciphertextChunk is required");
    }

    @Test
    void shouldRejectInvalidHashHeader() {
        assertThatThrownBy(() -> mapper.toInput(new byte[]{1}, "not base64"))
                .isInstanceOf(InvalidRequestException.class)
                .hasMessage("Invalid Base64 value");
    }
}
