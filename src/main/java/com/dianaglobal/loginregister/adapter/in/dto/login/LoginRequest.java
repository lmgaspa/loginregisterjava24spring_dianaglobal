// src/main/java/com/dianaglobal/loginregister/adapter/in/dto/LoginRequest.java
package com.dianaglobal.loginregister.adapter.in.dto.login;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public record LoginRequest(
        @NotBlank
        @Email(message = "Invalid e-mail")
        @Pattern(
                regexp = "^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$",
                message = "E-mail must contain a valid domain"
        )
        String email,

        @NotBlank String password
) {}
