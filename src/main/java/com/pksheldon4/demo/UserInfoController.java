package com.pksheldon4.demo;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;
import java.util.Map;

@RestController
@Slf4j
public class UserInfoController {

    @GetMapping("/user/info")
    public Map<String, Object> getUserInfo() {
        PreAuthenticatedAuthenticationToken authToken = (PreAuthenticatedAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();
        return Collections.singletonMap("user_name", ((User) authToken.getPrincipal()).getUsername());
    }
}