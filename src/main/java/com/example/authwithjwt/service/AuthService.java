package com.example.authwithjwt.service;

import com.example.authwithjwt.dto.AuthDto;
import com.example.authwithjwt.security.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;
import java.util.stream.Collectors;

//요청 -> AT 검사 -> AT 유효 -> 요청 실행
//요청 -> AT 검사 -> AT 기간만 만료 -> AT, RT로 재발급 요청 -> RT 유효 -> 재발급
//요청 -> AT 검사 -> AT 기간만 만료 -> AT, RT로 재발급 요청 -> RT 유효X -> 재로그인


@Slf4j
@Service
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class AuthService {
    private final JwtTokenProvider jwtTokenProvider;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;
    private final RedisService redisService;

    private final String SERVER = "Server";


    // 로그인
    @Transactional
    public AuthDto.TokenDto login(AuthDto.LoginDto loginDto) {
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(loginDto.getEmail(), loginDto.getPassword());

        Authentication authentication  = authenticationManagerBuilder.getObject().authenticate(authenticationToken);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        return generateToken(SERVER, authentication.getName(), getAuthorities(authentication)); //redis에 RT 저장후, TokenDto 반환
    }

    // 만료일자만 초과한 유효토큰인지 확인
    public boolean validate(String requestAccessTokenInHeader) {
        String requestAccessToken = resolveToken(requestAccessTokenInHeader);
        return jwtTokenProvider.validateAccessTokenOnlyExpired(requestAccessToken);
    }

    // AT와 RT 검사후, 토큰 재발급(validate 메서드가 true 일때만 반환 -> AT, RT 재발급
    @Transactional
    public AuthDto.TokenDto reissue(String requestAccessTokenInHeader, String requestRefreshToken) {
        String requestAccessToken = resolveToken(requestAccessTokenInHeader);

        Authentication authentication = jwtTokenProvider.getAuthentication(requestAccessToken);
        String principal = getPrincipal(requestAccessToken);

        String refreshTokenInRedis = redisService.getValues("RT("+SERVER+"):"+principal);
        if(refreshTokenInRedis == null) { // Redis에 저장되어 있는 RT가 없을 경우 (RT 유효 x)
            return null; // <- 재로그인 요청
        }

        if(!jwtTokenProvider.validateRefreshToken(requestRefreshToken) || !refreshTokenInRedis.equals(requestRefreshToken)) { // 탈취가능성 (RT 유효 x)
            redisService.deleteValues("RT("+SERVER+"):"+principal);
            return null; // <- 재로그인 요청
        }

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String authorities = getAuthorities(authentication);

        redisService.deleteValues("RT("+SERVER+"):"+principal); // 기존 RT 삭제
        AuthDto.TokenDto tokenDto = jwtTokenProvider.createToken(principal, authorities);
        saveRefreshToken(SERVER, principal, tokenDto.getRefreshToken());
        return tokenDto; // 재발급
    }

    // 로그아웃
    @Transactional
    public void logout(String requestAccessTokenInHeader) {
        String requestAccessToken = resolveToken(requestAccessTokenInHeader);
        String principal = getPrincipal(requestAccessToken);

        String refreshTokenInRedis = redisService.getValues("RT("+SERVER+"):"+principal);
        if(refreshTokenInRedis != null) {
            redisService.deleteValues("RT("+SERVER+"):"+principal);
        }

        // 로그아웃 처리한 AT를 저장하여 해당 AT를 이용한 요청 처리되지 않도록 함
        long expiration = jwtTokenProvider.getTokenExpirationTime(requestAccessToken) - new Date().getTime();
        redisService.setValuesWithTimeout(requestAccessToken, "logout", expiration);
    }



    // *******************************************************************
    // 공통 메서드

    // 토큰 발급
    @Transactional
    public AuthDto.TokenDto generateToken(String provider, String email, String authorities) {
        if(redisService.getValues("RT(" + provider + "):" + email) != null) {
            redisService.deleteValues("RT(" + provider + "):" + email);
        }

        AuthDto.TokenDto tokenDto = jwtTokenProvider.createToken(email, authorities);
        saveRefreshToken(provider, email, tokenDto.getRefreshToken());
        return tokenDto;
    }

    // RT를 Redis에 저장
    @Transactional
    public void saveRefreshToken(String provider, String principal, String refreshToken) {
        redisService.setValuesWithTimeout("RT(" + provider + "):" + principal, refreshToken, jwtTokenProvider.getTokenExpirationTime(refreshToken));
    }

    public String getAuthorities(Authentication authentication) {
        return authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));
    }

    public String getPrincipal(String requestAccessToken) {
        return jwtTokenProvider.getAuthentication(requestAccessToken).getName();
    }

    public String resolveToken(String requestAccessTokenInHeader) {
        if(requestAccessTokenInHeader != null && requestAccessTokenInHeader.startsWith("Bearer ")) {
            return requestAccessTokenInHeader.substring(7);
        }
        return null;
    }
}
