package com.example.leam_spring_security.resources;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
public class TodoResource {

    private Logger logger = LoggerFactory.getLogger(getClass());

    public static final List<Todo> TODOS_LIST = List.of(new Todo("user", "1234"),
            new Todo("user2", "1234"));

    @GetMapping("/todos")
    public List<Todo> retrieveAllTodos() {
        return TODOS_LIST;
    }

    @GetMapping("/users/{username}/todos")
    public Todo retrieveAllTodosForSpecificUser(@PathVariable String username) {
        return TODOS_LIST.get(0);
    }

    // CSRF 토큰 요청 한거를 인증 헤더에 넣고 다시 돌리면 사용 가능
    @PostMapping("/users/{username}/todos")
    public void createTodosForSpecificUser(@PathVariable String username, @RequestBody Todo todo) {
        logger.info("Create {} for {}", todo, username);
    }
}

record Todo (String username, String description) {}
