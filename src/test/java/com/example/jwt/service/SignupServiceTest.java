package com.example.jwt.service;

import com.example.jwt.dto.SignupDTO;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

import static org.junit.jupiter.api.Assertions.*;

@Transactional
@SpringBootTest
class SignupServiceTest {

    @Autowired
    private SignupService signupService;

    @Test
    void signupProcess(){
        //given
        SignupDTO signupDTO = new SignupDTO();
        signupDTO.setEmail("asd123@naver.com");
        signupDTO.setPassword("1234");
        String successMessage = "성공!";

        //when
        try{
            signupService.signupProcess(signupDTO);
        } catch(Exception e){
            successMessage = e.getMessage();
        }

        //then
        System.out.println(successMessage);
    }

    @Test
    void existByEmail() {
    }
}