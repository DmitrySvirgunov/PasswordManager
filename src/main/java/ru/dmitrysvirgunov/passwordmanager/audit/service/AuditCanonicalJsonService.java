package ru.dmitrysvirgunov.passwordmanager.audit.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.JsonNodeFactory;
import tools.jackson.databind.node.ObjectNode;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

@Component
@RequiredArgsConstructor
public class AuditCanonicalJsonService {

    private final ObjectMapper objectMapper;

    public JsonNode canonicalize(JsonNode node) {
        if (node == null || node.isNull()) {
            return JsonNodeFactory.instance.nullNode();
        }

        if (node.isObject()) {
            ObjectNode sorted = JsonNodeFactory.instance.objectNode();

            List<String> fieldNames = new ArrayList<>();
            for (Map.Entry<String, JsonNode> entry : node.properties()) {
                fieldNames.add(entry.getKey());
            }
            Collections.sort(fieldNames);

            for (String fieldName : fieldNames) {
                sorted.set(fieldName, canonicalize(node.get(fieldName)));
            }

            return sorted;
        }

        if (node.isArray()) {
            var array = JsonNodeFactory.instance.arrayNode();
            for (JsonNode item : node) {
                array.add(canonicalize(item));
            }
            return array;
        }

        return node;
    }

    public byte[] toCanonicalBytes(JsonNode node) {
        try {
            return objectMapper.writeValueAsBytes(canonicalize(node));
        } catch (Exception e) {
            throw new IllegalStateException("Failed to serialize canonical audit metadata", e);
        }
    }
}