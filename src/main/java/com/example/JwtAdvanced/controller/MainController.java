package com.example.JwtAdvanced.controller;

import com.example.JwtAdvanced.dto.CustomUserDetails;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MainController {
    @GetMapping("/")
    public String mainP(@AuthenticationPrincipal CustomUserDetails customUserDetails){
        String username=customUserDetails.getUsername();
        System.out.println("username"+username);
        return "main controller"+username;
    }
}
