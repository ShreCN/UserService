package com.example.userservice.configurations;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfigs {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http.authorizeHttpRequests(request -> {
            try {
                request.anyRequest().permitAll()
                        .and().cors().disable()
                        .csrf().disable();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }).build();
    }
}
