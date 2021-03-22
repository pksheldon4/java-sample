package com.pksheldon4.demo;

import org.springframework.boot.actuate.trace.http.HttpExchangeTracer;
import org.springframework.boot.actuate.trace.http.HttpTraceRepository;
import org.springframework.boot.actuate.trace.http.InMemoryHttpTraceRepository;
import org.springframework.boot.actuate.web.trace.servlet.HttpTraceFilter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.servlet.http.HttpServletRequest;

@Configuration
@ConditionalOnProperty(prefix = "management.trace.http", name = "enabled", matchIfMissing = true)
public class TraceConfig {

    @Bean
    public HttpTraceRepository inMemoryTraceRepository() {
        return new InMemoryHttpTraceRepository();
    }

    @Bean
    public HttpTraceFilter traceFilter(HttpTraceRepository repository, HttpExchangeTracer tracer) {
        return new TraceRequestFilter(repository, tracer);
    }


    static class TraceRequestFilter extends HttpTraceFilter {

        public TraceRequestFilter(HttpTraceRepository repository, HttpExchangeTracer tracer) {
            super(repository, tracer);
        }

        @Override
        protected boolean shouldNotFilter(HttpServletRequest request) {
            return request.getServletPath().contains("actuator") ||
                request.getServletPath().contains("favicon.ico");
        }
    }
}
