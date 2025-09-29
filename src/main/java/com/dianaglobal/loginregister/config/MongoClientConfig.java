package com.dianaglobal.loginregister.config;

import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoClients;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class MongoClientConfig {
    @Bean
    MongoClient mongoClient(@Value("${MONGODB_URI}") String uri) {
        return MongoClients.create(uri);
    }
}