package com.example.authwithjwt.domain;


import com.example.authwithjwt.dto.AuthDto;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.persistence.*;

@Entity(name = "users")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "user_id")
    private Long id;


    private String email;

    private String password;

    @Enumerated(EnumType.STRING)
    private Role role;


    // == 생성 메서드 == //
    public static User registerUser(AuthDto.SignupDto signupDto) {
        User user = new User();
        user.email = signupDto.getEmail();
        user.password = signupDto.getPassword();
        user.role = Role.USER;

        return user;
    }
}
