package com.cobra.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {
    @GetMapping("/hello")
    public String hello() {
        return "Hello World";
    }

    @GetMapping("/me")
    public Object getMe(){
        return SecurityContextHolder.getContext().getAuthentication();
    }

    @GetMapping("/me/v1")
    public Object getMeV1(Authentication authentication){
        return authentication;
    }

    @GetMapping("/me/v2")
    public Object getMeV2(@AuthenticationPrincipal UserDetails authentication){
        return authentication;
    }

}
