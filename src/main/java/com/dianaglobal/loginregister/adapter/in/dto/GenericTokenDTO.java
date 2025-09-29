package com.dianaglobal.loginregister.adapter.in.dto;

import jakarta.validation.constraints.NotBlank;

public record GenericTokenDTO(@NotBlank String token) {}
