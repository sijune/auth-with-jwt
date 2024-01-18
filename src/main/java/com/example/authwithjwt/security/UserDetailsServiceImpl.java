package com.example.authwithjwt.security;

import com.example.authwithjwt.domain.User;
import com.example.authwithjwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {
    private final UserRepository userRepository;

    @Override
    public UserDetailsImpl loadUserByUsername(String email) throws UsernameNotFoundException {
        User findUser = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("Can't find user with this email. -> " + email));
        if(findUser != null) {
            UserDetailsImpl userDetails = new UserDetailsImpl(findUser);
            return userDetails; //이 객체를 가지고 인증을 진행한다.
        }
        return null;
    }
}
