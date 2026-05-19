package ru.dmitrysvirgunov.passwordmanager.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "app.anti-abuse")
public record AntiAbuseProperties(
        boolean enabled,
        int emailLimit,
        long emailWindowMinutes,
        int ipLimit,
        long ipWindowMinutes,
        int loginEmailLimit,
        long loginEmailWindowMinutes,
        int loginIpLimit,
        long loginIpWindowMinutes,
        int preloginEmailLimit,
        int preloginIpLimit,
        long preloginWindowMinutes,
        int verifyEmailIpLimit,
        long verifyEmailWindowMinutes,
        int inviteLookupActorLimit,
        int inviteLookupVaultLimit,
        int inviteLookupTargetLimit,
        long inviteLookupWindowMinutes,
        int inviteCreateActorLimit,
        int inviteCreateVaultLimit,
        int inviteCreateTargetLimit,
        long inviteCreateWindowMinutes
) {
}
