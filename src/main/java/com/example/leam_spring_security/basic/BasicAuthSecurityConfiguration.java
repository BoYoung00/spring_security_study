package com.example.leam_spring_security.basic;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

// 필터 체인 (CSRF 없이 사용 하는 방법)
@Configuration
public class BasicAuthSecurityConfiguration {

    // HttpSecurity : HTTP 요청에 대한 웹 기반 보안 설정할 수 있음
    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(
            auth -> {
                auth.anyRequest().authenticated(); // 모든 요청 인증
            });

        // 섹션
        // ALWAYS : 항상 생성
        // NEVER : 세션 생성 안 하지만, 있으면 사용
        // IF_REQUIRED (필요) : 필요 시 생성
        // STATELESS (없는) : 세선 생성X, 사용X
        http.sessionManagement(
            session ->
            session.sessionCreationPolicy(SessionCreationPolicy.STATELESS) // 섹션 생성 정책
        );

        http.httpBasic(); // Basic 인증 활성화

        http.csrf().disable(); // CSRF 사용 중지
       return http.build();
    }
}

