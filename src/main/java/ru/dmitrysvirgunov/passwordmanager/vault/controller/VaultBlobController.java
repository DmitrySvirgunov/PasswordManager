package ru.dmitrysvirgunov.passwordmanager.vault.controller;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import ru.dmitrysvirgunov.passwordmanager.vault.dto.request.CompleteVaultBlobUploadRequest;
import ru.dmitrysvirgunov.passwordmanager.vault.dto.request.CreateVaultBlobRequest;
import ru.dmitrysvirgunov.passwordmanager.vault.dto.response.blob.VaultBlobPartResponse;
import ru.dmitrysvirgunov.passwordmanager.vault.dto.response.blob.VaultBlobResponse;
import ru.dmitrysvirgunov.passwordmanager.vault.dto.response.command.CompleteVaultBlobUploadResponse;
import ru.dmitrysvirgunov.passwordmanager.vault.dto.response.command.CreateVaultBlobResponse;
import ru.dmitrysvirgunov.passwordmanager.vault.mapper.CompleteVaultBlobUploadRequestMapper;
import ru.dmitrysvirgunov.passwordmanager.vault.mapper.CreateVaultBlobRequestMapper;
import ru.dmitrysvirgunov.passwordmanager.vault.mapper.UploadVaultBlobPartRequestMapper;
import ru.dmitrysvirgunov.passwordmanager.vault.model.CompleteVaultBlobUploadInput;
import ru.dmitrysvirgunov.passwordmanager.vault.model.CreateVaultBlobInput;
import ru.dmitrysvirgunov.passwordmanager.vault.model.UploadVaultBlobPartInput;
import ru.dmitrysvirgunov.passwordmanager.vault.service.VaultBlobService;

import java.net.URI;
import java.util.Base64;
import java.util.UUID;

@Validated
@RestController
@RequestMapping("/vaults/{vaultId}/blobs")
@RequiredArgsConstructor
public class VaultBlobController {

    public static final String CIPHERTEXT_CHUNK_SHA256_HEADER = "X-Ciphertext-Chunk-Sha256";
    public static final String CIPHERTEXT_SIZE_BYTES_HEADER = "X-Ciphertext-Size-Bytes";

    private final VaultBlobService vaultBlobService;
    private final CompleteVaultBlobUploadRequestMapper completeVaultBlobUploadRequestMapper;
    private final CreateVaultBlobRequestMapper createVaultBlobRequestMapper;
    private final UploadVaultBlobPartRequestMapper uploadVaultBlobPartRequestMapper;

    @PostMapping
    public ResponseEntity<CreateVaultBlobResponse> createBlob(
            @PathVariable UUID vaultId,
            @Valid @RequestBody CreateVaultBlobRequest request,
            @AuthenticationPrincipal Jwt jwt
    ) {
        CreateVaultBlobInput input = createVaultBlobRequestMapper.toInput(request);
        CreateVaultBlobResponse response = vaultBlobService.createBlob(vaultId, input, jwt);

        URI location = ServletUriComponentsBuilder
                .fromCurrentRequest()
                .path("/{blobId}")
                .buildAndExpand(response.blobId())
                .toUri();

        return ResponseEntity.created(location).body(response);
    }

    @PutMapping(
            value = "/{blobId}/parts/{partNumber}",
            consumes = MediaType.APPLICATION_OCTET_STREAM_VALUE
    )
    public ResponseEntity<Void> uploadBlobPart(
            @PathVariable UUID vaultId,
            @PathVariable UUID blobId,
            @PathVariable @Min(1) int partNumber,
            @RequestHeader(CIPHERTEXT_CHUNK_SHA256_HEADER) @NotBlank String ciphertextChunkSha256Base64,
            @RequestBody byte[] ciphertextChunk,
            @AuthenticationPrincipal Jwt jwt
    ) {
        UploadVaultBlobPartInput input = uploadVaultBlobPartRequestMapper.toInput(
                ciphertextChunk,
                ciphertextChunkSha256Base64
        );
        vaultBlobService.uploadBlobPart(vaultId, blobId, partNumber, input, jwt);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/{blobId}/complete")
    public ResponseEntity<CompleteVaultBlobUploadResponse> completeBlobUpload(
            @PathVariable UUID vaultId,
            @PathVariable UUID blobId,
            @Valid @RequestBody CompleteVaultBlobUploadRequest request,
            @AuthenticationPrincipal Jwt jwt
    ) {
        CompleteVaultBlobUploadInput input = completeVaultBlobUploadRequestMapper.toInput(request);
        return ResponseEntity.ok(
                vaultBlobService.completeBlobUpload(vaultId, blobId, input, jwt)
        );
    }

    @DeleteMapping("/{blobId}")
    public ResponseEntity<Void> abortBlob(
            @PathVariable UUID vaultId,
            @PathVariable UUID blobId,
            @AuthenticationPrincipal Jwt jwt
    ) {
        vaultBlobService.abortBlob(vaultId, blobId, jwt);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/{blobId}")
    public ResponseEntity<VaultBlobResponse> getBlob(
            @PathVariable UUID vaultId,
            @PathVariable UUID blobId,
            @AuthenticationPrincipal Jwt jwt
    ) {
        return ResponseEntity.ok(
                vaultBlobService.getBlob(vaultId, blobId, jwt)
        );
    }

    @GetMapping(
            value = "/{blobId}/parts/{partNumber}",
            produces = MediaType.APPLICATION_OCTET_STREAM_VALUE
    )
    public ResponseEntity<byte[]> getBlobPart(
            @PathVariable UUID vaultId,
            @PathVariable UUID blobId,
            @PathVariable @Min(1) int partNumber,
            @AuthenticationPrincipal Jwt jwt
    ) {
        VaultBlobPartResponse part = vaultBlobService.getBlobPart(vaultId, blobId, partNumber, jwt);

        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .contentLength(part.ciphertextSizeBytes())
                .header(
                        CIPHERTEXT_CHUNK_SHA256_HEADER,
                        Base64.getEncoder().encodeToString(part.ciphertextChunkSha256())
                )
                .header(CIPHERTEXT_SIZE_BYTES_HEADER, String.valueOf(part.ciphertextSizeBytes()))
                .header(
                        HttpHeaders.ACCESS_CONTROL_EXPOSE_HEADERS,
                        CIPHERTEXT_CHUNK_SHA256_HEADER + ", " + CIPHERTEXT_SIZE_BYTES_HEADER
                )
                .body(part.ciphertextChunk());
    }
}
