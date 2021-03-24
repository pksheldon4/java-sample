package com.pksheldon4.demo;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import lombok.extern.slf4j.Slf4j;
import org.apache.tomcat.util.codec.binary.Base64;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedGrantedAuthoritiesUserDetailsService;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails;
import org.springframework.security.web.authentication.preauth.RequestHeaderAuthenticationFilter;

import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.List;

@Configuration
@Slf4j
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private static final String X_FORWARDED_ACCESS_TOKEN = "X-Forwarded-Access-Token";
    private static final String X_FORWARDED_EMAIL = "X-Forwarded-Email";

    private final ObjectMapper mapper;

    SecurityConfig(ObjectMapper mapper) {
        this.mapper = mapper;
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
            .antMatchers(HttpMethod.GET, "/hello").hasRole("READ")
            //This is an example of a invalid request, when the scope/role doesn't exist
            .antMatchers(HttpMethod.GET, "/invalid").hasRole("INVALID")
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

    private void createAuthoritiesFromToken(String accessToken, List<GrantedAuthority> authorities) throws JsonProcessingException {
        String[] split_string = accessToken.split("\\.");
        String base64EncodedBody = split_string[1];
        String base64DecodedBody = new String(Base64.decodeBase64(base64EncodedBody));
        JsonNode jsonNode = mapper.readTree(base64DecodedBody);
        ArrayNode roles = (ArrayNode) jsonNode.get("user_roles");  //This field name matches the one created in Keycloak
        if (null != roles) {
            log.debug("#### ROLES: {}" + roles);
            roles.spliterator().forEachRemaining(role -> {
                    authorities.add(new SimpleGrantedAuthority("ROLE_" + role.textValue().toUpperCase()));
                }
            );
        }
    }

}