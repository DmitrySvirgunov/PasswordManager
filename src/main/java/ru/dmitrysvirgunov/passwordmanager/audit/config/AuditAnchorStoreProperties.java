package ru.dmitrysvirgunov.passwordmanager.audit.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Getter
@Setter
@Component
@ConfigurationProperties(prefix = "app.audit.anchor-store")
public class AuditAnchorStoreProperties {

    private boolean enabled = false;
    private String sourceInstanceId = "default";
    private String url;
    private String username;
    private String password;
    private String driverClassName = "org.postgresql.Driver";
    private boolean autoInitSchema = true;
    private long initialDelayMs = 15000;
    private long intervalMs = 30000;
    private int batchSize = 100;
}
