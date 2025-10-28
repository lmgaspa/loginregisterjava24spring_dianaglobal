// src/main/java/.../adapter/in/dto/OAuthGoogleRequest.java
package com.dianaglobal.loginregister.adapter.in.dto;

import jakarta.validation.constraints.NotBlank;

public record OAuthGoogleRequest(
        @NotBlank String idToken
) {}