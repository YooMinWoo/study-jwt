package com.example.jwt.service;

import com.example.jwt.dto.SignupDTO;
import com.example.jwt.mapper.UserMapper;
import com.example.jwt.security.config.PasswordEncoderConfig;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class SignupService {

    private final PasswordEncoder passwordEncoder;
    private final UserMapper userMapper;

    public void signupProcess(SignupDTO signupDTO) throws Exception {

        String email = signupDTO.getEmail();
        String password = signupDTO.getPassword();
        if(existByEmail(email)) throw new Exception("이미 존재하는 아이디입니다.");

        signupDTO.setPassword(passwordEncoder.encode(password));
        signupDTO.setRole("ROLE_ADMIN");

        userMapper.signup(signupDTO);
    }

    public boolean existByEmail(String email){
        return userMapper.findEmail(email) != null;
    }
}
