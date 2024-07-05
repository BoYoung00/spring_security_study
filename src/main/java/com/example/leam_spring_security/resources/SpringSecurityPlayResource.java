package com.example.leam_spring_security.resources;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SpringSecurityPlayResource {

    @GetMapping("/csrf-token")
    public CsrfToken retrieveCsrfToken(HttpServletRequest request) {
//        CSRF 토크 요청 해보기
        return (CsrfToken) request.getAttribute("_csrf");
    }
}
