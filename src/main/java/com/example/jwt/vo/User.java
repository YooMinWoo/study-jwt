package com.example.jwt.vo;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
@AllArgsConstructor
public class User {
    private Long id;
    private String email;
    private String password;
    private String role;

    public User() {
    }
}
