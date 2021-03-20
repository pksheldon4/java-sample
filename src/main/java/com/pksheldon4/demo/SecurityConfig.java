package com.pksheldon4.demo;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails;
import org.springframework.security.web.authentication.preauth.RequestHeaderAuthenticationFilter;

import javax.servlet.http.HttpServletRequest;

@Configuration
@Profile("sso")
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.addFilter(requestHeaderAuthenticationFilter())
            .authorizeRequests()
            .antMatchers(HttpMethod.OPTIONS).permitAll()
            .antMatchers(HttpMethod.GET, "/actuator/**").permitAll()
            .anyRequest()
            .authenticated();
//            .and()
//            .oauth2ResourceServer()
//            .jwt();
    }

    private RequestHeaderAuthenticationFilter requestHeaderAuthenticationFilter() throws Exception {
        RequestHeaderAuthenticationFilter f = new RequestHeaderAuthenticationFilter();
        f.setPrincipalRequestHeader("X-Forwarded-User");
        f.setCredentialsRequestHeader("X-Forwarded-Access-Token");
        f.setAuthenticationManager(authenticationManager());
        f.setAuthenticationDetailsSource(
            (AuthenticationDetailsSource<HttpServletRequest, PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails>)
                (request) ->new PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails(
                    request,
                    AuthorityUtils.createAuthorityList("ROLE_AUTHENTICATED")
                )
        );
        f.setAuthenticationFailureHandler(new SimpleUrlAuthenticationFailureHandler());
        f.setExceptionIfHeaderMissing(false);
        return f;
    }
}