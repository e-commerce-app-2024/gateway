package com.ecommerce.app.config;


import jakarta.validation.constraints.NotNull;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;

import java.util.Collection;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Configuration
public class JwtAuthConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    private final JwtGrantedAuthoritiesConverter authoritiesConverter = new JwtGrantedAuthoritiesConverter();
    @Value("${tesla.oauth2.client.name}")
    private String clientId;
    @Value("${tesla.oauth2.claim.name:preferred_username}")
    private String claimName;

    @Override
    public AbstractAuthenticationToken convert(@NotNull Jwt jwt) {
        var authorities = Stream.concat(
                authoritiesConverter.convert(jwt).stream(), extractResourceRoles(jwt)).collect(Collectors.toSet());
        return new JwtAuthenticationToken(jwt, authorities, getPrincipleName(jwt));
    }

    private String getPrincipleName(Jwt jwt) {
        String claimName = JwtClaimNames.SUB;
        if (this.claimName != null) {
            claimName = this.claimName;
        }
        return jwt.getClaim(claimName).toString();
    }

    private Stream<? extends GrantedAuthority> extractResourceRoles(Jwt jwt) {
        Map<String, Map<String, Object>> resourceAccess;
        Map<String, Object> clients;
        Collection<String> roles;
        if (jwt.getClaim("resource_access") == null) {
            return Stream.of();
        }
        resourceAccess = jwt.getClaim("resource_access");
        if (resourceAccess.get(clientId) == null) {
            return Stream.of();
        }
        clients = resourceAccess.get(clientId);
        roles = (Collection<String>) clients.get("roles");
        return roles.stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role));
    }
}
