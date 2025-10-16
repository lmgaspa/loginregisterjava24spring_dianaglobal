package com.dianaglobal.loginregister.application.service;

import java.util.UUID;

public interface AccountConfirmationTokenService {

    //** Emite um novo token com validade em minutos. */
    String issue(UUID userId, int minutes);

    /** Invalida todos os tokens válidos do usuário. */
    void invalidateAllFor(UUID userId);

    /**
     * Consome (marca como usado) e valida o token.
     * Lança IllegalArgumentException se inválido/expirado/já usado.
     */
    /** Consome o token (uso único); lança se inválido/expirado/usado. */
    ConfirmationPayload consume(String rawToken);

    /** Payload retornado pelo consume(...) */
    record ConfirmationPayload(UUID userId) {}
}
