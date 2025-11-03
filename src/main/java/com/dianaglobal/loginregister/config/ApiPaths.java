package com.dianaglobal.loginregister.config;

public final class ApiPaths {
    private ApiPaths() {}

    public static final String API_V1_BASE       = "/api/v1";
    public static final String AUTH_BASE         = API_V1_BASE + "/auth";
    public static final String AUTH_PASSWORD     = AUTH_BASE + "/password";
    public static final String AUTH_EMAIL        = AUTH_BASE + "/email";
    public static final String AUTH_COOKIE_PATH  = AUTH_BASE; // <- usar no cookie
    public static final String CONFIRM_BASE      = API_V1_BASE + "/confirm";
    public static final String USER_BASE         = API_V1_BASE + "/user";
}
