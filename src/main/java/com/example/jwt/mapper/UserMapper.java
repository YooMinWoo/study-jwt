package com.example.jwt.mapper;

import com.example.jwt.dto.SignupDTO;
import com.example.jwt.vo.User;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface UserMapper {
    User findEmail(String email);

    void signup(SignupDTO signupDTO);
}
