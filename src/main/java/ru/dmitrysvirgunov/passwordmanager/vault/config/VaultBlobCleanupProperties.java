package ru.dmitrysvirgunov.passwordmanager.vault.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

@Getter
@Setter
@ConfigurationProperties(prefix = "app.vault.blob-cleanup")
public class VaultBlobCleanupProperties {

    private boolean enabled = true;
    private long initialDelayMs = 300_000;
    private long intervalMs = 600_000;
    private Duration pendingMaxAge = Duration.ofHours(1);
    private Duration readyMaxAge = Duration.ofMinutes(15);
    private int batchSize = 100;
}
