package com.dianaglobal.loginregister.application.service;

import java.util.UUID;

public interface AccountConfirmationTokenService {

    /** Emite um token (string) com validade em minutos para o usuário. */
    String issue(UUID userId, int minutes);

    /**
     * Consome (marca como usado) e valida o token.
     * Lança IllegalArgumentException se inválido/expirado/já usado.
     */
    ConfirmationPayload consume(String token);

    /** Payload mínimo devolvido ao confirmar. */
    record ConfirmationPayload(UUID userId) {}
}
