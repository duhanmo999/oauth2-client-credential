package sample;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.web.SecurityFilterChain;

import java.time.Duration;

/**
 * OAuth resource configuration.
 */
public class OAuth2ResourceServerSecurityConfiguration {

    @Value("${spring.security.oauth2.resourceserver.jwt.jwk-set-uri}")
    String jwkSetUri;

    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
    String issuerUri;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests((authorize) -> authorize
                        .antMatchers(HttpMethod.GET, "/message/**").hasAuthority("SCOPE_message:read")
                        .antMatchers(HttpMethod.POST, "/message/**").hasAuthority("SCOPE_message:write")
                        .anyRequest().authenticated()
                )
                .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);
        return http.build();
    }

    @Bean
    JwtDecoder jwtDecoder() {
        NimbusJwtDecoder jwtDecoder = (NimbusJwtDecoder)
                JwtDecoders.fromIssuerLocation(issuerUri);
        OAuth2TokenValidator<Jwt> withClockSkew = new DelegatingOAuth2TokenValidator<>(
                new JwtTimestampValidator(Duration.ofSeconds(10)),
                new JwtIssuerValidator(issuerUri));
        jwtDecoder.setJwtValidator(withClockSkew);
        return jwtDecoder;
    }

}
