package com.example.springsecurityjwt.config;

import com.example.springsecurityjwt.handler.AccessDeniedExceptionHandler;
import com.example.springsecurityjwt.handler.AuthenticationExceptionHandler;
import com.example.springsecurityjwt.properties.SecurityCorsProperties;
import com.example.springsecurityjwt.properties.SecurityJwtProperties;
import com.example.springsecurityjwt.security.authentication.MemberAuthenticationConverter;
import com.example.springsecurityjwt.security.authentication.MemberAuthenticationProvider;
import com.example.springsecurityjwt.security.userdetails.MemberDetailsService;
import com.example.springsecurityjwt.utility.jwt.JwtProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.*;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.CorsUtils;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
// WebSecurityConfigurerAdapter가 Deprecated 됨에 따라 상속받아 오버라이딩하는 대신 Bean으로 직접 등록
public class WebSecurityConfig {

    private final SecurityCorsProperties securityCorsProperties;

    @Bean
    public SecurityFilterChain securityFilterChain(final HttpSecurity http,
                                                   final AuthenticationFilter authenticationFilter) throws Exception {
        http.authorizeRequests() // 스프링 시큐리티 적용, 선택적으로 적용되어야 하는 보안 구성 설정에 사용 (권한에 따른 요청 허용 등)
                .antMatchers(HttpMethod.GET, "/", "/register", "/login").permitAll() // 회원 기능에 대한 View는 모든 사용자가 요청 가능
                .antMatchers(HttpMethod.GET, "/admin").hasAuthority("관리자") // 관리자 페이지에 대한 View는 관리자만 요청 가능
                .antMatchers(HttpMethod.HEAD, "/api/member/email/**").anonymous() // 이메일 존재 여부 체크 API는 로그인하지 않은 사용자만 요청 가능
                .antMatchers(HttpMethod.POST, "/api/member").anonymous() // 회원가입 API는 로그인하지 않은 사용자만 요청 가능
                .antMatchers(HttpMethod.POST, "/api/member/login").anonymous() // 로그인 API는 로그인하지 않은 사용자만 요청 가능
                .anyRequest().authenticated() // 인증된 사용자만 요청 가능
                .and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // 세션 비활성화
                .and()
                .exceptionHandling()
                .authenticationEntryPoint(authenticationEntryPoint()) // 인증 예외 핸들러 등록
                .accessDeniedHandler(accessDeniedHandler()) // 인가 예외 핸들러 등록
                .and()
                .httpBasic().disable() // HTTP Basic 인증 비활성화
                .formLogin().disable() // Form 로그인 비활성화
                .logout().disable() // 로그아웃 기능 비활성화
                .rememberMe().disable() // Remember Me 기능 비활성화
                .headers().disable() // 응답 보안 헤더 비활성화
                .csrf().disable() // CSRF 보호 비활성화
                .cors().configurationSource(corsConfigurationSource()) // CORS 정책 설정
                .and()
                .addFilterBefore(authenticationFilter, UsernamePasswordAuthenticationFilter.class); // 인증 필터 추가

        return http.build();
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return web -> web.ignoring() // 스프링 시큐리티를 생략, 전역적으로 적용되어야 하는 보안 구성 설정에 사용 (특정 리소스에 대한 Security 무시 등)
                .requestMatchers(CorsUtils::isPreFlightRequest) // Pre-flight 요청에 대한 Security 무시
                .requestMatchers(PathRequest.toStaticResources().atCommonLocations()) // 정적 자원에 대한 Security 무시
                .requestMatchers(PathRequest.toH2Console()); // H2 콘솔에 대한 Security 무시
    }

    @Bean
    public AuthenticationEntryPoint authenticationEntryPoint() {
        return new AuthenticationExceptionHandler();
    }

    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        return new AccessDeniedExceptionHandler();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        final CorsConfiguration corsConfiguration = new CorsConfiguration();

        corsConfiguration.setAllowCredentials(securityCorsProperties.isAllowCredentials()); // 자격 증명 허용 여부 설정
        corsConfiguration.setAllowedHeaders(securityCorsProperties.getAllowedHeaders()); // 허용되는 헤더 목록 설정
        corsConfiguration.setAllowedMethods(securityCorsProperties.getAllowedMethods()); // 허용되는 HTTP 메서드 목록 설정
        corsConfiguration.setAllowedOrigins(securityCorsProperties.getAllowedOrigins()); // 허용되는 출처 목록 설정
        corsConfiguration.setMaxAge(securityCorsProperties.getMaxAge()); // Pre-flight 요청에 대한 응답 캐시 시간 설정

        final UrlBasedCorsConfigurationSource corsConfigurationSource = new UrlBasedCorsConfigurationSource();

        corsConfigurationSource.registerCorsConfiguration("/**", corsConfiguration); // CORS 정책 적용 범위를 모든 경로로 설정

        return corsConfigurationSource;
    }

    @Bean
    public AuthenticationFilter authenticationFilter(final AuthenticationManager authenticationManager,
                                                     final AuthenticationConverter authenticationConverter) {
        final AuthenticationFilter authenticationFilter = new AuthenticationFilter(authenticationManager, authenticationConverter);

        authenticationFilter.setSuccessHandler(authenticationSuccessHandler()); // 인증 성공 핸들러 설정
        authenticationFilter.setFailureHandler(authenticationFailureHandler()); // 인증 실패 핸들러 설정

        return authenticationFilter;
    }

    @Bean
    public AuthenticationManager authenticationManager(final AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public AuthenticationConverter authenticationConverter() {
        return new MemberAuthenticationConverter();
    }

    @Bean
    public AuthenticationSuccessHandler authenticationSuccessHandler() {
        return (request, response, authentication) -> SecurityContextHolder.getContext().setAuthentication(authentication); // 인증 성공 시 SecurityContextHolder에 Authentication 저장
    }

    @Bean
    public AuthenticationFailureHandler authenticationFailureHandler() {
        return new AuthenticationEntryPointFailureHandler(authenticationEntryPoint());
    }

    @Bean
    public AuthenticationProvider authenticationProvider(final AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> authenticationUserDetailsService) {
        return new MemberAuthenticationProvider(authenticationUserDetailsService);
    }

    @Bean
    public AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> authenticationUserDetailsService(final JwtProvider jwtProvider) {
        return new MemberDetailsService(jwtProvider);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public JwtProvider jwtProvider(final SecurityJwtProperties properties) {
        return new JwtProvider(properties);
    }

}