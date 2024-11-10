package com.example.jwt.controller;

import com.example.jwt.dto.SignupDTO;
import com.example.jwt.service.SignupService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class SignupController {

    private final SignupService signupService;

    @PostMapping("/signup")
    public String signup(SignupDTO signupDTO){
        try{
            signupService.signupProcess(signupDTO);
        } catch (Exception e){
            return e.getMessage();
        }
        return "회원가입 성공!";
    }
}
