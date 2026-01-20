package com.easyacco.authserver.config;

import com.easyacco.authserver.dto.CustomUserDetails;
import com.easyacco.authserver.service.CustomUserDetailsService;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private static final long EXPIRATION_TIME = 2000 * 60 * 60; // 1 hour

    @Autowired
    public CustomUserDetailsService customUserDetailsService;

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public CorsFilter corsFilter() {
        CorsConfiguration config = new CorsConfiguration();

        config.setAllowedOrigins(List.of("http://localhost:5173"));
        config.setAllowedMethods(List.of("GET","POST", "OPTIONS"));
        config.setAllowedHeaders(List.of("Authorization", "Content-Type"));
        config.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source =
                new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/oauth2/**", config);
        source.registerCorsConfiguration("/userinfo", config);
        source.registerCorsConfiguration("/userinfo", config);

        return new CorsFilter(source);
    }

    @Bean
    @Order(1)
    public SecurityFilterChain securityFilterChainForAuth(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        http .csrf(AbstractHttpConfigurer::disable);
            http.oauth2ResourceServer(oauth2 -> oauth2.jwt());
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class).oidc(oidc -> oidc
                .userInfoEndpoint(userInfo ->
                        userInfo.userInfoMapper(oidcUserInfoMapper())
                ));
        http.exceptionHandling(e -> e.authenticationEntryPoint(
                new LoginUrlAuthenticationEntryPoint("/login")
        ));
        return http .build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain appSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(req -> req.requestMatchers(
                        "/.well-known/**",
                        "/favicon.ico", "/userinfo").permitAll()

                        .requestMatchers(
                                "/oauth2/**",
                                "/login",
                                "/error"
                        ).permitAll()

                        .anyRequest().authenticated())
                .formLogin(Customizer.withDefaults())
                ;
        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return username -> {
            // Fetch user from DB
            UserDetails user = customUserDetailsService.loadUserByUsername(username);
            return user;
        };
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository() {

        TokenSettings tokenSettings = TokenSettings.builder()
                .accessTokenTimeToLive(Duration.ofMinutes(120))  // 15 min access token
                .refreshTokenTimeToLive(Duration.ofDays(7))     // 7 days refresh token
                .reuseRefreshTokens(true)
                .build();

        var registerClientBackendApi = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("easy-accounting")
                .clientSecret("secret")
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .redirectUri("http://localhost:5173/callback")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .authorizationGrantTypes(grantType -> {
                    grantType.add(AuthorizationGrantType.AUTHORIZATION_CODE);
                    grantType.add(AuthorizationGrantType.REFRESH_TOKEN);
                    grantType.add(AuthorizationGrantType.CLIENT_CREDENTIALS);
                })
                .clientSettings(ClientSettings.builder().requireProofKey(true).build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(120)) // ⬅ increase here
                        .refreshTokenTimeToLive(Duration.ofDays(7))
                        .build())
                .build();

        return new InMemoryRegisteredClientRepository(registerClientBackendApi);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }

    // TODO replace this creation on startup and provide it via env vars, some secret manager etc ...
    @Bean
    public JWKSource<SecurityContext> jwkSource() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);

        var keys = keyPairGenerator.generateKeyPair();
        var publicKey = (RSAPublicKey) keys.getPublic();
        var privateKey = keys.getPrivate();

        var rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();

        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider(UserDetailsService userDetailsService,
                                                            PasswordEncoder passwordEncoder) {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder);
        return provider;
    }

    @Bean
    WebSecurityCustomizer webSecurityCustomizer() {
        return web -> web.ignoring()
                .requestMatchers(
                        "/.well-known/**",
                        "/favicon.ico"
                );
    }

    @Bean
    public java.util.function.Function<OidcUserInfoAuthenticationContext, OidcUserInfo>
    oidcUserInfoMapper() {

        return context -> {

            var principal = context.getAuthorization().getPrincipalName();

            // 🔁 Fetch from DB
            CustomUserDetails user =
                    (CustomUserDetails) customUserDetailsService.loadUserByUsername(principal);

            Map<String, Object> claims = new HashMap<>();
            claims.put("sub", user.getUsername());
            claims.put("full_name", user.getFullName());
            claims.put("id", user.getId());

            return new OidcUserInfo(claims);
        };
    }


}
