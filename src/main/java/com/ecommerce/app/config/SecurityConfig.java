package com.ecommerce.app.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Bean
    SecurityWebFilterChain securityFilterChain(ServerHttpSecurity serverHttpSecurity) {

        serverHttpSecurity
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeExchange(exchange -> exchange
                        .pathMatchers("/eureka/**").permitAll()
                        .anyExchange().authenticated());

        serverHttpSecurity
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(jwtConfigurer -> Customizer.withDefaults()));

        return serverHttpSecurity.build();
    }

}
