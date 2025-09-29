// src/main/java/com/dianaglobal/loginregister/adapter/in/dto/ResetPasswordRequest.java
package com.dianaglobal.loginregister.adapter.in.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record ResetPasswordRequest(
        @NotBlank String token,

        @NotBlank
        @Size(min = 8, message = "Password must be at least 8 characters long")
        @Pattern(
                regexp = "^(?=.*[A-Z])(?=.*[a-z])(?=.*\\d).{8,}$",
                message = "Password must include at least 1 uppercase letter, 1 lowercase letter, and 1 digit"
        )
        String newPassword
) {}
