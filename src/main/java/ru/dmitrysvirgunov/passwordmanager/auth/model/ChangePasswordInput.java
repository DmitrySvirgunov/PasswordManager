package ru.dmitrysvirgunov.passwordmanager.auth.model;

import ru.dmitrysvirgunov.passwordmanager.common.model.AeadParams;

public record ChangePasswordInput(
        byte[] currentAuthSecret,
        byte[] newAuthSecret,
        KdfParams newClientKdfParams,
        byte[] newWrappedAccountRootKey,
        AeadParams newAccountRootWrapParams
) {
}
