package ru.dmitrysvirgunov.passwordmanager.audit.mapper;

import org.springframework.stereotype.Component;
import ru.dmitrysvirgunov.passwordmanager.audit.dto.response.AuditEventResponse;
import ru.dmitrysvirgunov.passwordmanager.audit.entity.AuditEvent;

import java.util.Base64;

@Component
public class AuditResponseMapper {

    public AuditEventResponse toResponse(AuditEvent event) {
        return toResponse(event, null, null, null);
    }

    public AuditEventResponse toResponse(
            AuditEvent event,
            String actorEmail,
            String targetUserEmail,
            String inviteeEmail
    ) {
        Base64.Encoder encoder = Base64.getEncoder();

        return new AuditEventResponse(
                event.getEventId(),
                event.getActorUserId(),
                actorEmail,
                event.getScopeType(),
                event.getScopeId(),
                event.getEventType(),
                event.getMeta(),
                targetUserEmail,
                inviteeEmail,
                encoder.encodeToString(event.getEventHash()),
                event.getPrevEventHash() != null ? encoder.encodeToString(event.getPrevEventHash()) : null,
                event.getSignatureKeyId(),
                encoder.encodeToString(event.getEventSignature()),
                event.getCreatedAt()
        );
    }
}
