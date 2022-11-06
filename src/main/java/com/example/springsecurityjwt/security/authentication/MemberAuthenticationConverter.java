package com.example.springsecurityjwt.security.authentication;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.web.util.WebUtils;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

@RequiredArgsConstructor
// HttpServletRequest를 Authentication로 변환하기 위한 클래스
public class MemberAuthenticationConverter implements AuthenticationConverter {

    private final AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource;

    public MemberAuthenticationConverter() {
        this(new WebAuthenticationDetailsSource());
    }

    @Override
    public Authentication convert(final HttpServletRequest request) {
        final Cookie accessTokenCookie = WebUtils.getCookie(request, "accessToken");

        if (accessTokenCookie == null) {
            return null;
        }

        final String accessToken = accessTokenCookie.getValue();

        final PreAuthenticatedAuthenticationToken result = new PreAuthenticatedAuthenticationToken(null, accessToken);

        result.setDetails(authenticationDetailsSource.buildDetails(request));

        return result;
    }

}