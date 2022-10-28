package com.example.springsecurityjwt.properties;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.ConstructorBinding;

@ConfigurationProperties(prefix = "security.jwt")
@ConstructorBinding
@RequiredArgsConstructor
@Getter
public class SecurityJwtProperties {

    private final String secretKey;

    private final int validSeconds;

}