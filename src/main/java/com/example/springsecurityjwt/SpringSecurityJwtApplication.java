package com.example.springsecurityjwt;

import com.example.springsecurityjwt.properties.SecurityCorsProperties;
import com.example.springsecurityjwt.properties.SecurityJwtProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties({
        SecurityCorsProperties.class,
        SecurityJwtProperties.class
})
public class SpringSecurityJwtApplication {

    public static void main(final String[] args) {
        SpringApplication.run(SpringSecurityJwtApplication.class, args);
    }

}