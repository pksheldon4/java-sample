package com.pksheldon4.demo;

import com.pksheldon4.demo.custom.KeycloakOAuth2UserService;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final KeycloakOAuth2UserService keycloakOauth2UserService;

    public SecurityConfig(OAuth2ClientProperties auth2ClientProperties) {
        this.keycloakOauth2UserService = new KeycloakOAuth2UserService(jwtDecoder(auth2ClientProperties));

    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.cors()
            .and()
            .authorizeRequests()
            .antMatchers(HttpMethod.GET, "/hello").hasAnyRole("readme", "clientread")
            .anyRequest().authenticated()
            .and()
            .oauth2Login()
            .userInfoEndpoint().userService(keycloakOauth2UserService);
    }


    JwtDecoder jwtDecoder(OAuth2ClientProperties auth2ClientProperties) {
        String uri = auth2ClientProperties.getProvider().get("keycloak").getJwkSetUri();
        return NimbusJwtDecoder.withJwkSetUri(uri).build();
    }
}
