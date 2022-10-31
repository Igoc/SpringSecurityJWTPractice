package com.example.springsecurityjwt.security.userdetails;

import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.springsecurityjwt.utility.jwt.JwtProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

@RequiredArgsConstructor
@Slf4j
// 사용자의 데이터를 로드하기 위한 클래스
public class MemberDetailsService implements AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> {

    private final JwtProvider jwtProvider;

    @Override
    // PreAuthenticatedAuthenticationToken을 기반으로 UserDetails 생성
    public UserDetails loadUserDetails(final PreAuthenticatedAuthenticationToken token) throws AuthenticationException {
        try {
            final String accessToken = (String) token.getCredentials();
            final DecodedJWT result = jwtProvider.verify(accessToken);

            final String email = result.getClaim("email").asString();
            final String nickname = result.getClaim("nickname").asString();
            final String[] role = {result.getClaim("role").asString()};

            log.info("Member authentication request: {}, {}, {}, {}", accessToken, email, nickname, role);

            return MemberDetails.builder()
                    .email(email)
                    .nickname(nickname)
                    .authorities(role)
                    .build();
        } catch (JWTVerificationException ex) {
            throw new BadCredentialsException(ex.getMessage());
        }
    }

}