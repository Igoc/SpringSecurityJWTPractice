package com.example.springsecurityjwt.service;

import com.auth0.jwt.exceptions.JWTCreationException;
import com.example.springsecurityjwt.domain.Member;
import com.example.springsecurityjwt.domain.enumeration.Role;
import com.example.springsecurityjwt.dto.MemberLoginRequestDto;
import com.example.springsecurityjwt.dto.MemberLoginResponseDto;
import com.example.springsecurityjwt.dto.MemberRegisterRequestDto;
import com.example.springsecurityjwt.dto.MemberRegisterResponseDto;
import com.example.springsecurityjwt.exception.MemberException;
import com.example.springsecurityjwt.repository.MemberRepository;
import com.example.springsecurityjwt.status.MemberStatus;
import com.example.springsecurityjwt.utility.jwt.JwtProvider;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Service
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class MemberService {

    private final MemberRepository memberRepository;

    private final ModelMapper modelMapper;

    private final PasswordEncoder passwordEncoder;

    private final JwtProvider jwtProvider;

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

    public MemberLoginResponseDto login(final MemberLoginRequestDto requestDto) throws JWTCreationException {
        final Optional<Member> result = memberRepository.findByEmail(requestDto.getEmail());

        if (result.isEmpty()) {
            throw new MemberException(MemberStatus.NOT_EXISTING_EMAIL);
        }

        final Member member = result.get();

        if (!passwordEncoder.matches(requestDto.getPassword(), member.getPassword())) {
            throw new MemberException(MemberStatus.INCORRECT_PASSWORD);
        }

        final Map<String, String> payload = new HashMap<>();
        payload.put("email", member.getEmail());
        payload.put("nickname", member.getNickname());
        payload.put("role", member.getRole().getDisplayName());

        return MemberLoginResponseDto.builder()
                .accessToken(jwtProvider.generate(payload))
                .build();
    }

}