package com.example.springsecurityjwt.service;

import com.example.springsecurityjwt.domain.Member;
import com.example.springsecurityjwt.domain.enumeration.Role;
import com.example.springsecurityjwt.dto.MemberRegisterRequestDto;
import com.example.springsecurityjwt.dto.MemberRegisterResponseDto;
import com.example.springsecurityjwt.exception.MemberException;
import com.example.springsecurityjwt.repository.MemberRepository;
import com.example.springsecurityjwt.status.MemberStatus;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class MemberService {

    private final MemberRepository memberRepository;

    private final ModelMapper modelMapper;

    private final PasswordEncoder passwordEncoder;

    public boolean checkEmailExistence(final String email) {
        return memberRepository.findByEmail(email).isPresent();
    }

    @Transactional
    public MemberRegisterResponseDto register(final MemberRegisterRequestDto requestDto) {
        if (checkEmailExistence(requestDto.getEmail())) {
            throw new MemberException(MemberStatus.EXISTING_EMAIL);
        }

        final Member member = Member.builder()
                .email(requestDto.getEmail())
                .password(passwordEncoder.encode(requestDto.getPassword()))
                .nickname(requestDto.getNickname())
                .role((requestDto.isAdmin()) ? (Role.ADMIN) : (Role.USER))
                .build();

        final Member result = memberRepository.save(member);

        return modelMapper.map(result, MemberRegisterResponseDto.class);
    }

}