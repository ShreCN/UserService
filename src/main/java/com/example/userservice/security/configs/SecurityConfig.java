package com.example.userservice.security.configs;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Collections;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    // 1. A Spring Security filter chain for the Protocol Endpoints.
    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
            throws Exception {
//        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
//        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
//                .oidc(Customizer.withDefaults());	// Enable OpenID Connect 1.0
//        http
//                // Redirect to the login page when not authenticated from the
//                // authorization endpoint
//                .exceptionHandling((exceptions) -> exceptions
//                        .defaultAuthenticationEntryPointFor(
//                                new LoginUrlAuthenticationEntryPoint("/login"),
//                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
//                        )
//                )
//                // Accept access tokens for User Info and/or Client Registration
//                .oauth2ResourceServer((resourceServer) -> resourceServer
//                        .jwt(Customizer.withDefaults()));
//
//        return http.build();

        http
                .authorizeHttpRequests((authz) -> authz
                                .anyRequest().permitAll()
//                        .and().cors().disable()
//                        .csrf().disable()
                );
        return http.build();
    }

//    2. A Spring Security filter chain for authentication.
    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
            throws Exception {
        http
                .authorizeHttpRequests((authorize) -> authorize
                        .anyRequest().authenticated()
                )
                // Form login handles the redirect to the login page from the
                // authorization server filter chain
                .formLogin(Customizer.withDefaults());

        return http.build();
    }

//  3.  An instance of UserDetailsService for retrieving users to authenticate.
//    @Bean
//    public UserDetailsService userDetailsService() {
//        UserDetails userDetails = User.builder()
//                .username("user1")
//                .password("$2a$12$rQuLwvHWIMqyHwMfogSpe.MOOHVtEotxD3WiooSj9hnCHFQjw.CzK")
//                .roles("USER")
//                .build();
//
//        return new InMemoryUserDetailsManager(userDetails);
//    }

//  4.   An instance of RegisteredClientRepository for managing clients.
//    @Bean
//    public RegisteredClientRepository registeredClientRepository() {
//        RegisteredClient oidcClient = RegisteredClient.withId(UUID.randomUUID().toString())
//                .clientId("scaler")
//                .clientSecret("$2a$16$AKFF5FLx1.CIgJp5UX6BSu0.DLN6WYGoL4o4.d0vNH.P1w6iB8aP.")
//                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
//                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
//                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
//                .redirectUri("https://oauth.pstmn.io/v1/callback")
//                .postLogoutRedirectUri("https://oauth.pstmn.io/v1/callback")
//                .scope("ADMIN")
//                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
//                .build();
//
//        return new InMemoryRegisteredClientRepository(oidcClient);
//    }
// 5. 	An instance of com.nimbusds.jose.jwk.source.JWKSource for signing access tokens.
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }
//	6. An instance of java.security.KeyPair with keys generated on startup used to create the JWKSource above.
    private static KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        }
        catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }
//  7.  An instance of JwtDecoder for decoding signed access tokens.
    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }
//	8. An instance of AuthorizationServerSettings to configure Spring Authorization Server.
    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }

//    @Bean
//    public OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer() {
//        return (context) -> {
//            // Check if the token type is ACCESS_TOKEN
//            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
//                context.getClaims().claims((claims) -> {
//                    // Extract roles from the user's authorities, removing the "ROLE_" prefix
//                    Set<String> roles = AuthorityUtils.authorityListToSet(context.getPrincipal().getAuthorities())
//                            .stream()
//                            .map(c -> c.replaceFirst("^ROLE_", ""))
//                            .collect(Collectors.collectingAndThen(Collectors.toSet(), Collections::unmodifiableSet));
//
//                    // Add the roles to the claims
//                    claims.put("roles", roles);
//
//                    // Uncomment and modify the following line to add user ID to the claims if needed
//                    // claims.put("userId", userId);
//                });
//            }
//        };
//    }
//@Bean
//public OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer() {
//    return (context) -> {
//        if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
//            context.getClaims().claims((claims) -> {
//                Set<String> roles = AuthorityUtils.authorityListToSet(context.getPrincipal().getAuthorities())
//                        .stream()
//                        .map(c -> c.replaceFirst("^ROLE_", ""))
//                        .collect(Collectors.collectingAndThen(Collectors.toSet(), Collections::unmodifiableSet));
//                claims.put("roles", roles);
//            });
//        }
//    };
//}
}
