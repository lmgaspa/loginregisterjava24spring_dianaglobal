package com.dianaglobal.loginregister.adapter.in.dto.email;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Pattern;

public record ChangeEmailRequest(

        @Email(message="Invalid e-mail")
        @Pattern(
                regexp="^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$",
                message="E-mail must contain a valid domain"
        )
        String newEmail
) {}
