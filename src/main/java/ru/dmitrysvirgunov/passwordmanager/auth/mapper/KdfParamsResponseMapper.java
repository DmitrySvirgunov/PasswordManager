package ru.dmitrysvirgunov.passwordmanager.auth.mapper;

import org.springframework.stereotype.Component;
import ru.dmitrysvirgunov.passwordmanager.auth.dto.response.KdfParamsResponse;
import ru.dmitrysvirgunov.passwordmanager.auth.model.KdfParams;

import java.util.Base64;

@Component
public class KdfParamsResponseMapper {

    public KdfParamsResponse toResponse(KdfParams kdfParams) {
        return new KdfParamsResponse(
                kdfParams.algorithm(),
                kdfParams.iterations(),
                kdfParams.memoryKb(),
                kdfParams.parallelism(),
                Base64.getEncoder().encodeToString(kdfParams.salt())
        );
    }
}