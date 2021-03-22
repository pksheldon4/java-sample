package com.pksheldon4.demo;

import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDateTime;

@RestController
@Slf4j
public class HelloController {

    @GetMapping(path = "/hello")
    public String hello() {
        log.info("/hello was called");
        return "Welcome to Java-Sample Hello";
    }
}
