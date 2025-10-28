package com.dianaglobal.loginregister.consent.adapter.in.web;

import com.dianaglobal.loginregister.consent.domain.ConsentDecision;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class ConsentPayloadDTO {
    @NotBlank
    private String version;                 // "2025-10-01"
    private ConsentDecision decision;       // accept_all | reject_all | custom
    private ConsentCategoriesDTO categories;
}
