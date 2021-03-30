package com.pksheldon4.demo;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedGrantedAuthoritiesUserDetailsService;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails;
import org.springframework.security.web.authentication.preauth.RequestHeaderAuthenticationFilter;

import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Configuration
@Slf4j
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private static final String X_FORWARDED_ACCESS_TOKEN = "X-Forwarded-Access-Token";
    private static final String X_FORWARDED_EMAIL = "X-Forwarded-Email";

    private final JwtDecoder jwtDecoder;

    public SecurityConfig(@Value("${spring.security.oauth2.resourceserver.jwt.jwk-set-uri}") String jwkSetUri) {
        this.jwtDecoder = NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();
    }


    private AuthenticationProvider authenticationProvider() {
        PreAuthenticatedAuthenticationProvider authProvider = new PreAuthenticatedAuthenticationProvider();
        authProvider.setPreAuthenticatedUserDetailsService(new PreAuthenticatedGrantedAuthoritiesUserDetailsService());
        return authProvider;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder authenticationManagerBuilder) {
        authenticationManagerBuilder.authenticationProvider(authenticationProvider());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.cors()
            .and()
            .addFilter(requestHeaderAuthenticationFilter())
            .authorizeRequests()

            // /hello and /user/info require READ scope/role
            .antMatchers(HttpMethod.GET, "/hello").hasAnyAuthority("SCOPE_read")
            //This is an example of a invalid request, when the scope/role doesn't exist
            .antMatchers(HttpMethod.GET, "/invalid").hasAuthority("SCOPE_invalid")
            //This requires that any request at least have had an x-forwarded-access-token in the header
            .anyRequest().hasRole("AUTHENTICATED");
    }

    private RequestHeaderAuthenticationFilter requestHeaderAuthenticationFilter() throws Exception {
        RequestHeaderAuthenticationFilter f = new RequestHeaderAuthenticationFilter();
        f.setPrincipalRequestHeader(X_FORWARDED_EMAIL);
        f.setCredentialsRequestHeader(X_FORWARDED_ACCESS_TOKEN);
        f.setAuthenticationManager(authenticationManager());
        f.setAuthenticationDetailsSource(authenticationDetailsSource());
        f.setAuthenticationFailureHandler(new SimpleUrlAuthenticationFailureHandler());
        f.setExceptionIfHeaderMissing(false);
        return f;
    }

    private AuthenticationDetailsSource<HttpServletRequest, PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails> authenticationDetailsSource() {
        return (request) -> new PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails(
            request,
            getGrantedAuthoritiesFromRequest(request)
        );
    }

    private List<GrantedAuthority> getGrantedAuthoritiesFromRequest(HttpServletRequest request) {
        String accessToken = request.getHeader(X_FORWARDED_ACCESS_TOKEN);
        List<GrantedAuthority> authorities = new ArrayList<>();
        try {
            if (accessToken != null) {
                createAuthoritiesFromToken(accessToken, authorities);
                /**
                 * Use this, along with "http.anyRequest().hasRole("AUTHENTICATED")" above, to ensure there's a token in the request header
                 */
                authorities.add(new SimpleGrantedAuthority("ROLE_AUTHENTICATED"));
            }
        } catch (Exception ex) {
            log.error("############## {}", ex.getLocalizedMessage());
            throw new RuntimeException(ex);
        }
        return authorities;
    }

    private void createAuthoritiesFromToken(String accessToken, List<GrantedAuthority> authorities) {
        Jwt jwt = jwtDecoder.decode(accessToken);
        authorities.addAll(scopeAuthorities(jwt));
        authorities.addAll(realmRoleAuthorities(jwt));
        authorities.addAll(clientRoleAuthorities(jwt));
    }

    private Collection<? extends GrantedAuthority> scopeAuthorities(Jwt jwt) {
        String scopeString = (String) jwt.getClaims().get("scope");
        String[] scopes = scopeString != null ? scopeString.split(" ") : new String[]{};
        return Arrays.stream(scopes).sequential()
            .map(scopeName -> "SCOPE_" + scopeName)
            .map(SimpleGrantedAuthority::new)
            .collect(Collectors.toSet());
    }

    private Collection<GrantedAuthority> realmRoleAuthorities(Jwt jwt) {

        if (jwt.containsClaim("realm_access")) {
            final Map<String, Object> realmAccess = (Map<String, Object>) jwt.getClaims().get("realm_access");
            if (realmAccess.containsKey("roles")) {
                return ((List<String>) realmAccess.get("roles")).stream()
                    .map(roleName -> "ROLE_" + roleName) // prefix to map to a Spring Security "role"
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toSet());
            }
        }
        return new HashSet<>();
    }

    private Collection<GrantedAuthority> clientRoleAuthorities(Jwt jwt) {
        final String clientId = (String) jwt.getClaims().get("azp"); //Client Name from Keycloak

        if (jwt.containsClaim("resource_access")) {
            final Map<String, Object> clientAccess = (Map<String, Object>) ((Map<String, Object>) jwt.getClaims().get("resource_access")).get(clientId);
            if (clientAccess != null && clientAccess.containsKey("roles")) {
                return ((List<String>) clientAccess.get("roles")).stream()
                    .map(roleName -> "ROLE_" + roleName) // prefix to map to a Spring Security "role"
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toSet());
            }
        }
        return new HashSet<>();
    }
}