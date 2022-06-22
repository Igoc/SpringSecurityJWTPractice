package com.example.springsecurityjwt.controller;

import com.example.springsecurityjwt.dto.member.*;
import com.example.springsecurityjwt.service.MemberService;
import com.example.springsecurityjwt.util.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class MemberController {

    private final MemberService memberService;
    private final PasswordEncoder passwordEncoder;

    @PostMapping("/member")
    public MemberSaveResponseDto saveMember(@RequestBody MemberSaveRequestDto memberSaveRequestDto) {
        memberSaveRequestDto.setPassword(passwordEncoder.encode(memberSaveRequestDto.getPassword()));

        return memberService.join(memberSaveRequestDto);
    }

    @PostMapping("/login")
    public MemberTokenResponseDto login(@RequestBody MemberLoginRequestDto memberLoginRequestDto) {
        MemberLoginResponseDto result = memberService.login(memberLoginRequestDto);

        Authentication authentication = new UsernamePasswordAuthenticationToken(result.getId(), null);
        String token = JwtTokenProvider.generateToken(authentication);

        return MemberTokenResponseDto.builder()
                .token(token)
                .build();
    }
}
