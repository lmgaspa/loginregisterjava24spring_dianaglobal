package com.dianaglobal.loginregister.config;

public final class ApiPaths {
    private ApiPaths() {}

    // Versão raiz
    public static final String API_V1_BASE       = "/api/v1";

    // Domínios principais da API
    public static final String AUTH_BASE         = API_V1_BASE + "/auth";
    public static final String AUTH_PASSWORD     = AUTH_BASE + "/password";
    public static final String AUTH_EMAIL        = AUTH_BASE + "/email";

    // Path que vai nos cookies httpOnly (refresh_token, csrf_token),
    // limitando o envio de cookies só pro escopo de auth
    public static final String AUTH_COOKIE_PATH  = AUTH_BASE;

    // (mantido pra futuro se quiser separar confirmação de conta em outro controller)
    public static final String CONFIRM_BASE      = API_V1_BASE + "/confirm";

    // Rotas de dados do usuário autenticado
    public static final String USER_BASE         = API_V1_BASE + "/user";
}
