package com.example.leam_spring_security.jwt;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.stream.Collectors;

@RestController
public class JwtAuthenticationResource {

    private JwtEncoder jwtEncoder;

    public JwtAuthenticationResource(JwtEncoder jwtEncoder) {
        this.jwtEncoder = jwtEncoder;
    }

    @PostMapping("/authenticate")
    public JwtResponse authenticate(Authentication authentication) {
        return new JwtResponse(createToken(authentication));
    }

    private String createToken(Authentication authentication) {
        // 토큰이 전달한 클레임(키값 쌍)을 나타내는 JSON 객체
        var claims =
                JwtClaimsSet.builder()
                            .issuer("self") // 발행자
                            .issuedAt(Instant.now()) // 발급 시간
                            .expiresAt(Instant.now().plusSeconds(60 * 15)) // 만료 시간
                            .subject(authentication.getName()) // 사용자명 또는 ID
                            .claim("scope", createScope(authentication)) // 권한 범위
                            .build();

        return jwtEncoder.encode(JwtEncoderParameters.from(claims))
                .getTokenValue(); // JWT 만들기
    }
    // 권한 관리
    private String createScope(Authentication authentication) {
        return authentication.getAuthorities().stream() // 사용권한 정보 가져오기.
                .map(a -> a.getAuthority())
                .collect(Collectors.joining(" ")); // 최종 연산(" " 결합)
    }
}

record JwtResponse(String token) {}