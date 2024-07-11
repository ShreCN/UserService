package com.example.userservice;

import com.example.userservice.security.services.JpaRegisteredClientRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

import java.util.UUID;
@SpringBootTest
class UserServiceApplicationTests {

    @Test
    void contextLoads() {
    }
    @Autowired
    JpaRegisteredClientRepository jpaRegisteredClientRepository;

    @Test
    public void addSampleRegisteredClient() {
        RegisteredClient oidcClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("scaler")// scaler
                .clientSecret("$2a$16$AKFF5FLx1.CIgJp5UX6BSu0.DLN6WYGoL4o4.d0vNH.P1w6iB8aP.") // secret
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("https://oauth.pstmn.io/v1/callback")
                .postLogoutRedirectUri("https://oauth.pstmn.io/v1/callback")
                .scope("ADMIN")
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
                .build();

        jpaRegisteredClientRepository.save(oidcClient);
    }

}
