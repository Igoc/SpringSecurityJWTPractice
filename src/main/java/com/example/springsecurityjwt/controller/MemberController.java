package com.example.springsecurityjwt.controller;

import com.example.springsecurityjwt.dto.MemberLoginRequestDto;
import com.example.springsecurityjwt.dto.MemberLoginResponseDto;
import com.example.springsecurityjwt.dto.MemberRegisterRequestDto;
import com.example.springsecurityjwt.dto.MemberRegisterResponseDto;
import com.example.springsecurityjwt.properties.SecurityJwtProperties;
import com.example.springsecurityjwt.service.MemberService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;

@RestController
@RequestMapping("/api/member")
@Validated
@RequiredArgsConstructor
public class MemberController {

    private final MemberService memberService;

    private final SecurityJwtProperties securityJwtProperties;

    @RequestMapping(value = "/email/{email}", method = RequestMethod.HEAD)
    public ResponseEntity<Void> checkEmailExistence(@PathVariable @NotBlank @Email final String email) {
        return (memberService.checkEmailExistence(email)) ?
                (ResponseEntity.ok().build()) :
                (ResponseEntity.notFound().build());
    }

    @PostMapping("")
    public ResponseEntity<MemberRegisterResponseDto> register(@RequestBody @Valid final MemberRegisterRequestDto requestDto) {
        final MemberRegisterResponseDto result = memberService.register(requestDto);

        return ResponseEntity.status(HttpStatus.CREATED).body(result);
    }

    @PostMapping("/login")
    public ResponseEntity<MemberLoginResponseDto> login(@RequestBody @Valid final MemberLoginRequestDto requestDto,
                                                        final HttpServletResponse response) {
        final MemberLoginResponseDto result = memberService.login(requestDto);

        final Cookie accessTokenCookie = new Cookie("accessToken", result.getAccessToken());

        accessTokenCookie.setPath("/"); // 쿠키 경로 설정
        accessTokenCookie.setMaxAge(securityJwtProperties.getValidSeconds()); // 쿠키 만료 시간 설정

        response.addCookie(accessTokenCookie);

        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

}