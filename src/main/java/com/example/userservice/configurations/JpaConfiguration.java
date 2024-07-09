package com.example.userservice.configurations;

import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

@Configuration
@EnableJpaAuditing
public class JpaConfiguration { // to auto update time stamps createdAt and updatedAt in BaseModel
}


