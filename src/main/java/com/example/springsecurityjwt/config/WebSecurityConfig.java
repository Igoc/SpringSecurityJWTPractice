package com.example.springsecurityjwt.config;

import com.example.springsecurityjwt.handler.AccessDeniedExceptionHandler;
import com.example.springsecurityjwt.handler.AuthenticationExceptionHandler;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
// WebSecurityConfigurerAdapter가 Deprecated 됨에 따라 상속받아 오버라이딩하는 대신 Bean으로 직접 등록
public class WebSecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(final HttpSecurity http) throws Exception {
        http.authorizeRequests() // 스프링 시큐리티 적용, 선택적으로 적용되어야 하는 보안 구성 설정에 사용 (권한에 따른 요청 허용 등)
                .anyRequest().authenticated() // 인증된 사용자만 요청 가능
                .and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // 세션 비활성화
                .and()
                .exceptionHandling()
                .authenticationEntryPoint(new AuthenticationExceptionHandler()) // 인증 예외 핸들러 등록
                .accessDeniedHandler(new AccessDeniedExceptionHandler()) // 인가 예외 핸들러 등록
                .and()
                .httpBasic().disable() // HTTP Basic 인증 비활성화
                .formLogin().disable() // Form 로그인 비활성화
                .logout().disable() // 로그아웃 기능 비활성화
                .rememberMe().disable() // Remember Me 기능 비활성화
                .headers().disable() // 응답 보안 헤더 비활성화
                .csrf().disable(); // CSRF 보호 비활성화

        return http.build();
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return web -> web.ignoring() // 스프링 시큐리티를 생략, 전역적으로 적용되어야 하는 보안 구성 설정에 사용 (특정 리소스에 대한 Security 무시 등)
                .requestMatchers(PathRequest.toStaticResources().atCommonLocations()) // 정적 자원에 대한 Security 무시
                .requestMatchers(PathRequest.toH2Console()); // H2 콘솔에 대한 Security 무시
    }

}