package com.example.springsecurityjwt.handler;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
// 인증 예외 핸들러
public class AuthenticationExceptionHandler implements AuthenticationEntryPoint {

    @Override
    public void commence(final HttpServletRequest request,
                         final HttpServletResponse response,
                         final AuthenticationException authException) throws IOException {
        log.warn("Authentication exception occurrence: {}", authException.getMessage());

        response.sendError(HttpStatus.UNAUTHORIZED.value(), authException.getMessage());
    }

}