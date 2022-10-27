package com.example.springsecurityjwt.handler;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
// 인가 예외 핸들러
public class AccessDeniedExceptionHandler implements AccessDeniedHandler {

    @Override
    public void handle(final HttpServletRequest request,
                       final HttpServletResponse response,
                       final AccessDeniedException accessDeniedException) throws IOException {
        log.warn("Access denied exception occurrence: {}", accessDeniedException.getMessage());

        response.sendError(HttpStatus.FORBIDDEN.value(), accessDeniedException.getMessage());
    }

}