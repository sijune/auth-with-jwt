package com.example.authwithjwt.configuration;


import com.example.authwithjwt.security.JwtAccessDeniedHandler;
import com.example.authwithjwt.security.JwtAuthenticationEntryPoint;
import com.example.authwithjwt.security.JwtAuthenticationFilter;
import com.example.authwithjwt.security.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true) //API별 권한 제어 가능
@RequiredArgsConstructor
public class SecurityConfig {
    private final JwtTokenProvider jwtTokenProvider;
    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;

    @Bean
    public BCryptPasswordEncoder encoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        //정적리소스 예외 설정
        return web -> web
                .ignoring()
                .requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf().disable() //JWT 토큰 사용할 것이므로 disable
                .httpBasic().disable() // REST 방식 사용할 것이므로 disable
                .formLogin().disable() // REST 방식 사용할 것이므로 disable
                .addFilterBefore(new JwtAuthenticationFilter(jwtTokenProvider), UsernamePasswordAuthenticationFilter.class)
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                // 인증성공 당시 security context 의 authentication을 참조하지 않는다.
                // 인증 후 클라이언트가 자원에 접근할 때는 항상 새로운 security context를 생성한다.

                .and()
                .exceptionHandling()
                .authenticationEntryPoint(jwtAuthenticationEntryPoint) //401 에러 핸들링, 잘못된 접근입니다.(인가 실패시)
                .accessDeniedHandler(jwtAccessDeniedHandler) //403 에러 핸들링, 권한이 없습니다. (인증 실패시)

                .and()
                .authorizeRequests()
                .antMatchers("/api/mypage/**").authenticated() //마이페이지는 인증필요
                .antMatchers("/api/admin/**").hasRole("ADMIN") //관리자 페이지
                .anyRequest().permitAll()

                .and()
                .headers()
                .frameOptions().sameOrigin();

        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

}


