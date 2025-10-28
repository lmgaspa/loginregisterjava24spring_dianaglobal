package com.dianaglobal.loginregister.application.service;

import java.time.Duration;
import java.util.UUID;

public interface EmailChangeTokenService {

    /** Dados retornados ao consumir o token com sucesso. */
    record Payload(UUID userId, String newEmail) {}

    /** Invalida todos os tokens ainda válidos do usuário (antes de emitir um novo). */
    void invalidateAllFor(UUID userId);

    /**
     * Emite um token bruto (retornado para envio por e-mail) e persiste apenas o hash.
     * @param userId                dono do token
     * @param newEmailNormalized    novo e-mail já normalizado (lower/trim)
     * @param ttl                   validade (ex.: Duration.ofMinutes(45))
     * @return token bruto (plaintext) para colocar no link
     */
    String issue(UUID userId, String newEmailNormalized, Duration ttl);

    /**
     * Consome (uso único) o token: valida existência, expiração e reuso.
     * Marca como consumido e inválido. Retorna o payload com userId e newEmail.
     * @throws IllegalArgumentException token inválido
     * @throws com.dianaglobal.loginregister.application.service.exception.TokenExpiredException token expirado
     * @throws com.dianaglobal.loginregister.application.service.exception.TokenAlreadyUsedException token já usado/revogado
     */
    Payload consume(String rawToken);
}
