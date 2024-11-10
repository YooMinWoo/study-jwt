package com.example.jwt.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
public class SignupDTO {

    private String email;
    private String password;
    private String role;

    public SignupDTO() {

    }
}
