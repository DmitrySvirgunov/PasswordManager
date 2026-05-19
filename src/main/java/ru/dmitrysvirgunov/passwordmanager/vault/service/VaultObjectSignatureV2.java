package ru.dmitrysvirgunov.passwordmanager.vault.service;

import ru.dmitrysvirgunov.passwordmanager.common.exception.InvalidRequestException;
import ru.dmitrysvirgunov.passwordmanager.common.model.AeadParams;
import ru.dmitrysvirgunov.passwordmanager.vault.model.BlobReferenceInput;
import tools.jackson.databind.JsonNode;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Comparator;
import java.util.List;

final class VaultObjectSignatureV2 {

    static final int FORMAT_VERSION = 2;

    private static final String SIGNATURE_CONTEXT = "pm.vault-object-envelope";

    private VaultObjectSignatureV2() {
    }

    static byte[] buildCanonicalBytes(VaultObjectSignaturePayload payload) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        writeUtf8(out, SIGNATURE_CONTEXT);
        writeInt(out, FORMAT_VERSION);

        writeUtf8(out, payload.contentAeadParams().algorithm());
        writeBytes(out, payload.contentAeadParams().iv());
        writeBytes(out, payload.ciphertext());

        AeadParams recordKeyWrapParams = extractAeadParams(payload.recordKeyWrapParams());
        writeUtf8(out, recordKeyWrapParams.algorithm());
        writeBytes(out, recordKeyWrapParams.iv());
        writeBytes(out, payload.wrappedRecordKey());

        List<BlobReferenceInput> sortedBlobReferences = payload.blobReferences().stream()
                .sorted(Comparator
                        .comparing((BlobReferenceInput blobReference) -> blobReference.role().name())
                        .thenComparing(blobReference -> blobReference.blobId().toString()))
                .toList();

        writeInt(out, sortedBlobReferences.size());
        for (BlobReferenceInput blobReference : sortedBlobReferences) {
            writeUtf8(out, blobReference.role().name());
            writeUtf8(out, blobReference.blobId().toString());
        }

        return out.toByteArray();
    }

    private static AeadParams extractAeadParams(JsonNode node) {
        if (node == null || !node.isObject()) {
            throw new InvalidRequestException("recordKeyWrapParams must be a JSON object");
        }

        JsonNode algorithmNode = node.get("algorithm");
        JsonNode ivBase64Node = node.get("ivBase64");

        if (algorithmNode == null || algorithmNode.asText().isBlank()) {
            throw new InvalidRequestException("recordKeyWrapParams.algorithm is required");
        }

        if (ivBase64Node == null || ivBase64Node.asText().isBlank()) {
            throw new InvalidRequestException("recordKeyWrapParams.ivBase64 is required");
        }

        try {
            return new AeadParams(
                    algorithmNode.asText(),
                    Base64.getDecoder().decode(ivBase64Node.asText())
            );
        } catch (IllegalArgumentException e) {
            throw new InvalidRequestException("recordKeyWrapParams.ivBase64 must be valid Base64", e);
        }
    }

    private static void writeInt(ByteArrayOutputStream out, int value) {
        out.write((value >>> 24) & 0xFF);
        out.write((value >>> 16) & 0xFF);
        out.write((value >>> 8) & 0xFF);
        out.write(value & 0xFF);
    }

    private static void writeBytes(ByteArrayOutputStream out, byte[] value) {
        byte[] safeValue = value == null ? new byte[0] : value;
        writeInt(out, safeValue.length);
        out.writeBytes(safeValue);
    }

    private static void writeUtf8(ByteArrayOutputStream out, String value) {
        writeBytes(out, value.getBytes(StandardCharsets.UTF_8));
    }
}
