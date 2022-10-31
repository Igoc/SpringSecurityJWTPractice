package com.example.springsecurityjwt.security.authentication;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

@RequiredArgsConstructor
// 특정 Authentication 구현체를 처리하기 위한 클래스
public class MemberAuthenticationProvider implements AuthenticationProvider {

    private final AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> authenticationUserDetailsService;

    @Override
    // 인증 수행
    public Authentication authenticate(final Authentication authentication) throws AuthenticationException {
        if (!supports(authentication.getClass())) {
            return null;
        }

        if (authentication.getCredentials() == null) {
            throw new BadCredentialsException("No access token credentials found in request");
        }

        final UserDetails userDetails = authenticationUserDetailsService.loadUserDetails((PreAuthenticatedAuthenticationToken) authentication);

        final PreAuthenticatedAuthenticationToken result = new PreAuthenticatedAuthenticationToken(userDetails, authentication.getCredentials(), userDetails.getAuthorities());

        result.setDetails(authentication.getDetails());

        return result;
    }

    @Override
    // Authentication 구현체 지원 여부 반환
    public boolean supports(Class<?> authentication) {
        return PreAuthenticatedAuthenticationToken.class.isAssignableFrom(authentication);
    }

}