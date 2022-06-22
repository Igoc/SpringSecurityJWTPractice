package com.example.springsecurityjwt.service;

import com.example.springsecurityjwt.domain.Member;
import com.example.springsecurityjwt.dto.member.MemberLoginRequestDto;
import com.example.springsecurityjwt.dto.member.MemberLoginResponseDto;
import com.example.springsecurityjwt.dto.member.MemberSaveRequestDto;
import com.example.springsecurityjwt.dto.member.MemberSaveResponseDto;
import com.example.springsecurityjwt.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class MemberService {

    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;

    public MemberSaveResponseDto join(MemberSaveRequestDto memberSaveRequestDto) {
        Member member = Member.builder()
                .id(memberSaveRequestDto.getId())
                .password(memberSaveRequestDto.getPassword())
                .name(memberSaveRequestDto.getName())
                .build();

        memberRepository.save(member);

        return MemberSaveResponseDto.builder()
                .id(member.getId())
                .name(member.getName())
                .build();
    }

    public MemberLoginResponseDto login(MemberLoginRequestDto memberLoginRequestDto) {
        Member member = memberRepository.findById(memberLoginRequestDto.getId())
                .orElseThrow(() -> new IllegalArgumentException("유효하지 않은 사용자"));

        if (!passwordEncoder.matches(memberLoginRequestDto.getPassword(), member.getPassword())) {
            throw new IllegalArgumentException("유효하지 않은 비밀번호");
        }

        return MemberLoginResponseDto.builder()
                .id(member.getId())
                .name(member.getName())
                .build();
    }
}
