package com.example.leam_spring_security.basic;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;

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

        http.headers().frameOptions().sameOrigin(); // 프레임 허용

       return http.build();
    }

    // 사용자 생성
//    @Bean
//    public UserDetailsService userDetailsService() {
//        var user = User.withUsername("user")
//                .password("{noop}1234")
//                .roles("USER") // 역할 할당
//                .build();
//
//        var admin = User.withUsername("admin")
//                .password("{noop}1234")
//                .roles("ADMIN") // 역할 할당
//                .build();
//
//        return new InMemoryUserDetailsManager(user, admin);
//    }

    // DataSource : DB 연결할 수 있는 방법을 제공하는 인터페이스
    @Bean
    public DataSource dataSource() {
        return new EmbeddedDatabaseBuilder() // 임베디드 DB를 생성하는 빌더 객체 생성
                .setType(EmbeddedDatabaseType.H2) // DB 유형 H2
                .addScript(JdbcDaoImpl.DEFAULT_USER_SCHEMA_DDL_LOCATION) // 기본 사용자 스키마 DDL 스크립트 추가
                .build();
    }

    // DataSource를 사용해서 DB에 사용자 정보를 넣는 함수
    @Bean
    public UserDetailsService userDetailsService(DataSource dataSource) {
        var user = User.withUsername("user")
                //.password("{noop}1234")
                .password("1234")
                .passwordEncoder(str -> passwordEncoder().encode(str))
                .roles("USER") // 역할 할당
                .build();

        var admin = User.withUsername("admin")
                .password("1234")
                .passwordEncoder(str -> passwordEncoder().encode(str))
                .roles("ADMIN", "USER") // 역할 할당
                .build();

        var jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);
        jdbcUserDetailsManager.createUser(user);
        jdbcUserDetailsManager.createUser(admin);

        return jdbcUserDetailsManager;
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}

