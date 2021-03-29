package com.pksheldon4.demo.custom;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequestEntityConverter;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.client.ResponseErrorHandler;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.client.UnknownContentTypeException;

import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * 90% of this is taken from DefaultOAuth2UserService but instead of creating a default "ROLE_USER" GrantedAuthority,
 * it parses the Keycloak realm_access and resource_access/{client-id} user-mapped
 * roles and creates GrantedAuthority out of them.
 */

public class KeycloakOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    public static final String REALM_ACCESS = "realm_access";
    public static final String ROLES = "roles";
    public static final String RESOURCE_ACCESS = "resource_access";
    public static final String KEYCLOAK_APP_ID_CLAIM = "azp";
    private static final String MISSING_USER_INFO_URI_ERROR_CODE = "missing_user_info_uri";
    private static final String MISSING_USER_NAME_ATTRIBUTE_ERROR_CODE = "missing_user_name_attribute";
    private static final String INVALID_USER_INFO_RESPONSE_ERROR_CODE = "invalid_user_info_response";
    private static final ParameterizedTypeReference<Map<String, Object>> PARAMETERIZED_RESPONSE_TYPE = new ParameterizedTypeReference<>() {
    };
    private final JwtDecoder decoder;
    private Converter<OAuth2UserRequest, RequestEntity<?>> requestEntityConverter = new OAuth2UserRequestEntityConverter();
    private RestOperations restOperations;

    public KeycloakOAuth2UserService(JwtDecoder jwtDecoder) {
        RestTemplate restTemplate = new RestTemplate();
        restTemplate.setErrorHandler(new OAuth2ErrorResponseErrorHandler());
        this.restOperations = restTemplate;
        this.decoder = jwtDecoder;
    }

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        Assert.notNull(userRequest, "userRequest cannot be null");
        if (!StringUtils
            .hasText(userRequest.getClientRegistration().getProviderDetails().getUserInfoEndpoint().getUri())) {
            OAuth2Error oauth2Error = new OAuth2Error(MISSING_USER_INFO_URI_ERROR_CODE,
                "Missing required UserInfo Uri in UserInfoEndpoint for Client Registration: "
                    + userRequest.getClientRegistration().getRegistrationId(),
                null);
            throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
        }
        String userNameAttributeName = userRequest.getClientRegistration().getProviderDetails().getUserInfoEndpoint()
            .getUserNameAttributeName();
        if (!StringUtils.hasText(userNameAttributeName)) {
            OAuth2Error oauth2Error = new OAuth2Error(MISSING_USER_NAME_ATTRIBUTE_ERROR_CODE,
                "Missing required \"user name\" attribute name in UserInfoEndpoint for Client Registration: "
                    + userRequest.getClientRegistration().getRegistrationId(),
                null);
            throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
        }
        RequestEntity<?> request = this.requestEntityConverter.convert(userRequest);
        ResponseEntity<Map<String, Object>> response = getResponse(userRequest, request);
        Map<String, Object> userAttributes = response.getBody();
        Set<GrantedAuthority> authorities = new LinkedHashSet<>();
        OAuth2AccessToken token = userRequest.getAccessToken();
        for (String authority : token.getScopes()) {
            authorities.add(new SimpleGrantedAuthority("SCOPE_" + authority));
        }
        addKeycloakRoleAuthorities(token, authorities);
        return new DefaultOAuth2User(authorities, userAttributes, userNameAttributeName);
    }

    private ResponseEntity<Map<String, Object>> getResponse(OAuth2UserRequest userRequest, RequestEntity<?> request) {
        try {
            return this.restOperations.exchange(request, PARAMETERIZED_RESPONSE_TYPE);
        } catch (OAuth2AuthorizationException ex) {
            OAuth2Error oauth2Error = ex.getError();
            StringBuilder errorDetails = new StringBuilder();
            errorDetails.append("Error details: [");
            errorDetails.append("UserInfo Uri: ")
                .append(userRequest.getClientRegistration().getProviderDetails().getUserInfoEndpoint().getUri());
            errorDetails.append(", Error Code: ").append(oauth2Error.getErrorCode());
            if (oauth2Error.getDescription() != null) {
                errorDetails.append(", Error Description: ").append(oauth2Error.getDescription());
            }
            errorDetails.append("]");
            oauth2Error = new OAuth2Error(INVALID_USER_INFO_RESPONSE_ERROR_CODE,
                "An error occurred while attempting to retrieve the UserInfo Resource: " + errorDetails.toString(),
                null);
            throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString(), ex);
        } catch (UnknownContentTypeException ex) {
            String errorMessage = "An error occurred while attempting to retrieve the UserInfo Resource from '"
                + userRequest.getClientRegistration().getProviderDetails().getUserInfoEndpoint().getUri()
                + "': response contains invalid content type '" + ex.getContentType().toString() + "'. "
                + "The UserInfo Response should return a JSON object (content type 'application/json') "
                + "that contains a collection of name and value pairs of the claims about the authenticated End-User. "
                + "Please ensure the UserInfo Uri in UserInfoEndpoint for Client Registration '"
                + userRequest.getClientRegistration().getRegistrationId() + "' conforms to the UserInfo Endpoint, "
                + "as defined in OpenID Connect 1.0: 'https://openid.net/specs/openid-connect-core-1_0.html#UserInfo'";
            OAuth2Error oauth2Error = new OAuth2Error(INVALID_USER_INFO_RESPONSE_ERROR_CODE, errorMessage, null);
            throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString(), ex);
        } catch (RestClientException ex) {
            OAuth2Error oauth2Error = new OAuth2Error(INVALID_USER_INFO_RESPONSE_ERROR_CODE,
                "An error occurred while attempting to retrieve the UserInfo Resource: " + ex.getMessage(), null);
            throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString(), ex);
        }
    }

    /**
     * Sets the {@link Converter} used for converting the {@link OAuth2UserRequest} to a
     * {@link RequestEntity} representation of the UserInfo Request.
     *
     * @param requestEntityConverter the {@link Converter} used for converting to a
     *                               {@link RequestEntity} representation of the UserInfo Request
     * @since 5.1
     */
    public final void setRequestEntityConverter(Converter<OAuth2UserRequest, RequestEntity<?>> requestEntityConverter) {
        Assert.notNull(requestEntityConverter, "requestEntityConverter cannot be null");
        this.requestEntityConverter = requestEntityConverter;
    }

    /**
     * Sets the {@link RestOperations} used when requesting the UserInfo resource.
     *
     * <p>
     * <b>NOTE:</b> At a minimum, the supplied {@code restOperations} must be configured
     * with the following:
     * <ol>
     * <li>{@link ResponseErrorHandler} - {@link OAuth2ErrorResponseErrorHandler}</li>
     * </ol>
     *
     * @param restOperations the {@link RestOperations} used when requesting the UserInfo
     *                       resource
     * @since 5.1
     */
    public final void setRestOperations(RestOperations restOperations) {
        Assert.notNull(restOperations, "restOperations cannot be null");
        this.restOperations = restOperations;
    }


    ////////////////////////////////////////
    // This is the new code which extracts out Keycloak User mapped roles (realm/client) and adds ROLE_* Granted Authorities
    ///////////////////////////////////////
    private void addKeycloakRoleAuthorities(OAuth2AccessToken token, Set<GrantedAuthority> authorities) {
        Jwt jwt = decoder.decode(token.getTokenValue());
        authorities.addAll(realmRoleAuthorities(jwt));
        authorities.addAll(clientRoleAuthorities(jwt));
    }

    private Collection<GrantedAuthority> realmRoleAuthorities(Jwt jwt) {

        if (jwt.containsClaim(REALM_ACCESS)) {
            final Map<String, Object> realmAccess = (Map<String, Object>) jwt.getClaims().get(REALM_ACCESS);
            if (realmAccess.containsKey(ROLES)) {
                return createAuthorities((List<String>) realmAccess.get(ROLES));
            }
        }
        return new HashSet<>();
    }

    private Collection<GrantedAuthority> clientRoleAuthorities(Jwt jwt) {
        if (jwt.containsClaim(KEYCLOAK_APP_ID_CLAIM) && jwt.containsClaim(RESOURCE_ACCESS)) {
            final String clientId = (String) jwt.getClaims().get(KEYCLOAK_APP_ID_CLAIM); //Client Name from Keycloak Auth Server
            Assert.notNull(clientId, "clientId cannot be null");
            final Map<String, Object> clientAccess = (Map<String, Object>) ((Map<String, Object>) jwt.getClaims().get(RESOURCE_ACCESS)).get(clientId);
            if (clientAccess != null && clientAccess.containsKey(ROLES)) {
                return createAuthorities((List<String>) clientAccess.get(ROLES));
            }
        }
        return new HashSet<>();
    }

    private Collection<GrantedAuthority> createAuthorities(List<String> roleNames) {
        return roleNames.stream()
            .map(roleName -> "ROLE_" + roleName)
            .map(SimpleGrantedAuthority::new)
            .collect(Collectors.toSet());
    }
}
