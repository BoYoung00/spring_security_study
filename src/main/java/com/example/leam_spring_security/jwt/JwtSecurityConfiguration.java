package com.example.leam_spring_security.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

// JWT
@Configuration
public class JwtSecurityConfiguration {

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

        http.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt); // Oauth 2.0 서버 jwt 설정

       return http.build();
    }

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

    // 인코더 선언
    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


    // JWT
    // 키 쌍 만들기 (JWT 1단계)
    @Bean
    public KeyPair keyPair() {
        try {
            var keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048); // 키 사이즈 (높을 수록 보안 좋음)
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    // 공개 키와 비밀 키가 있는 RSA 키 생성 및 구성 (JWT 2단계)
    @Bean
    public RSAKey rsaKey(KeyPair keyPair) {
        return new RSAKey.Builder((RSAPublicKey) keyPair.getPublic()) // 공개 키 설정
                .privateKey(keyPair.getPrivate()) // 비밀 키 설정
                .keyID(UUID.randomUUID().toString()) // 키 아이디 무작위 설정
                .build();
    }

    // 키가 있는 json 생성 (JWT 3단계)
    @Bean
    public JWKSource<SecurityContext> jwkSource(RSAKey rsaKey) {
        var jwkSet = new JWKSet(rsaKey);

        return (jwkSelector, context) -> jwkSelector.select(jwkSet); // jwkSet 선택
    }


    // 디코더 (JWT 4단계)
    @Bean
    public JwtDecoder jwtDecoder(RSAKey rsaKey) throws JOSEException {
        return NimbusJwtDecoder
                .withPublicKey(rsaKey.toRSAPublicKey()) // 공개 키
                .build();
    }

    // 인코더 (JWT 5단계)
    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        return new NimbusJwtEncoder(jwkSource);
    }
}

