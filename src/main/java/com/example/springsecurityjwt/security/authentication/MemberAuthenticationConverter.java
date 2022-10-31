package com.example.springsecurityjwt.security.authentication;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;

@RequiredArgsConstructor
// HttpServletRequest를 Authentication로 변환하기 위한 클래스
public class MemberAuthenticationConverter implements AuthenticationConverter {

    public static final String AUTHENTICATION_SCHEME = "Bearer";

    private final AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource;

    public MemberAuthenticationConverter() {
        this(new WebAuthenticationDetailsSource());
    }

    @Override
    public Authentication convert(final HttpServletRequest request) {
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);

        if (header == null) {
            return null;
        }

        header = header.trim();

        if (!StringUtils.startsWithIgnoreCase(header, AUTHENTICATION_SCHEME)) {
            return null;
        }

        if (header.equalsIgnoreCase(AUTHENTICATION_SCHEME)) {
            throw new BadCredentialsException("Empty " + AUTHENTICATION_SCHEME.toLowerCase() + " authentication token");
        }

        final String accessToken = header.substring(AUTHENTICATION_SCHEME.length() + 1);

        final PreAuthenticatedAuthenticationToken result = new PreAuthenticatedAuthenticationToken(null, accessToken);

        result.setDetails(authenticationDetailsSource.buildDetails(request));

        return result;
    }

}