package com.dianaglobal.loginregister.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SwaggerConfig {

    @Bean
    public OpenAPI api(
            @Value("${application.brand.name:Diana Global}") String brand,
            @Value("${application.version:1.0.0}") String version) {
        return new OpenAPI()
                .info(new Info()
                        .title(brand + " – API")
                        .version(version)
                        .description("Public authentication and password recovery endpoints."));
    }
}
