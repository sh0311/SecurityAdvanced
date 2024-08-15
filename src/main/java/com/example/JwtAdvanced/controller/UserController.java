package com.example.JwtAdvanced.controller;

import com.example.JwtAdvanced.dto.JoinDto;
import com.example.JwtAdvanced.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Repository;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {
    private final UserService userService;
    public UserController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/join")
    public ResponseEntity<String> joinUser(@RequestBody JoinDto joinDto){
        boolean res=userService.join(joinDto);
        if(res)
            return ResponseEntity.ok("회원가입 성공");
        return ResponseEntity.badRequest().body("회원가입 실패");
    }
}
