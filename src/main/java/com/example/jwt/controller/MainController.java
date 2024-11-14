package com.example.jwt.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class MainController {

    @GetMapping("/")
    public String mainP(){
        String name = SecurityContextHolder.getContext().getAuthentication().getName();
        return "Main Controller: "+name;
    }
}
