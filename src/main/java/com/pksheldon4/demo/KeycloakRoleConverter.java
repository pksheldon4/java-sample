package com.pksheldon4.demo;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class KeycloakRoleConverter implements Converter<Jwt, Collection<GrantedAuthority>> {
    @Override
    public Collection<GrantedAuthority> convert(Jwt jwt) {
        Set<GrantedAuthority> allAuthorities = new HashSet<>();
        allAuthorities.addAll(scopeAuthorities(jwt));
        allAuthorities.addAll(realmRoleAuthorities(jwt));
        allAuthorities.addAll(clientRoleAuthorities(jwt));
        return allAuthorities;
    }

    // The default JwtConverter Implementation coverts Scopes to Granted Authorities
    // So this just makes sure they're still included.
    private Collection<? extends GrantedAuthority> scopeAuthorities(Jwt jwt) {
        String scopeString = (String) jwt.getClaims().get("scope");
        String[] scopes = scopeString != null ? scopeString.split(" ") : new String[]{};
        return Arrays.stream(scopes).sequential()
            .map(scopeName -> "SCOPE_" + scopeName)
            .map(SimpleGrantedAuthority::new)
            .collect(Collectors.toSet());
    }

    private Collection<GrantedAuthority> realmRoleAuthorities(Jwt jwt) {

        final Map<String, Object> realmAccess = (Map<String, Object>) jwt.getClaims().get("realm_access");
        if (realmAccess != null && realmAccess.containsKey("roles")) {
            return ((List<String>) realmAccess.get("roles")).stream()
                .map(roleName -> "ROLE_" + roleName) // prefix to map to a Spring Security "role"
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toSet());
        }
        return new HashSet<>();
    }

    private Collection<GrantedAuthority> clientRoleAuthorities(Jwt jwt) {
        final String clientId = (String) jwt.getClaims().get("azp"); //Client Name from Keycloak

        final Map<String, Object> clientAccess = (Map<String, Object>) ((Map<String, Object>) jwt.getClaims().get("resource_access")).get(clientId);
        if (clientAccess != null && clientAccess.containsKey("roles")) {
            return ((List<String>) clientAccess.get("roles")).stream()
                .map(roleName -> "ROLE_" + roleName) // prefix to map to a Spring Security "role"
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toSet());
        }
        return new HashSet<>();
    }
}
