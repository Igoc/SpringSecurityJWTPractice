package com.example.springsecurityjwt;

import com.example.springsecurityjwt.properties.SecurityCorsProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties({SecurityCorsProperties.class})
public class SpringSecurityJwtApplication {

    public static void main(final String[] args) {
        SpringApplication.run(SpringSecurityJwtApplication.class, args);
    }

}