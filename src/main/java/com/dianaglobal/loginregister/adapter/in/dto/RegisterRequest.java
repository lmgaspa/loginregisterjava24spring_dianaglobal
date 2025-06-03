package com.dianaglobal.loginregister.adapter.in.dto;

import jakarta.validation.constraints.*;

public record RegisterRequest(
        @NotBlank String name,
        @NotBlank @Email String email,
        @NotBlank @Size(min = 8, message = "Password must be at least 8 characters long") String password
) {}
