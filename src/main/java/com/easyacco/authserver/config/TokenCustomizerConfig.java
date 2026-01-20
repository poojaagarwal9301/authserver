package com.easyacco.authserver.config;

import com.easyacco.authserver.dto.CustomUserDetails;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import java.security.Principal;

@Configuration
public class TokenCustomizerConfig {

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> oidcTokenCustomizer() {
        return context -> {

            // 🔑 THIS CHECK IS MANDATORY
            if (OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue())) {

                Authentication authentication = context.getPrincipal();
                Object principal = authentication.getPrincipal();

                if (principal instanceof CustomUserDetails user) {
                    context.getClaims().claim("full_name", user.getFullName());
                    context.getClaims().claim("id", user.getId());
                }
            }
        };
    }
}
