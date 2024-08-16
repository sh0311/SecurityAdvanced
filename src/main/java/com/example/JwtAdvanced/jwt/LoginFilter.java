package com.example.JwtAdvanced.jwt;

import com.example.JwtAdvanced.dto.CustomUserDetails;
import com.example.JwtAdvanced.entity.Refresh;
import com.example.JwtAdvanced.entity.User;
import com.example.JwtAdvanced.repository.RefreshRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;

// UsernamePasswordAuthenticationFilter가 AuthenticationManager에게 authenticationToken객체 던져주어 인증한다
// 필터 구현 후 SecurityConfig에 등록해야 필터 사용 가능
// UsernamePasswordAuthenticationFilter를 상속 받아 만들어졌기에 디폴트로 설정된 POST login 경로만 동작한다
public class LoginFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;
    private final JWTUtil jwtUtil;
    private final RefreshRepository refreshRepository;

    public LoginFilter(AuthenticationManager authenticationManager, JWTUtil jwtUtil, RefreshRepository refreshRepository) {
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
        this.refreshRepository = refreshRepository;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest req, HttpServletResponse res) throws AuthenticationException {
        try {
            ObjectMapper om = new ObjectMapper();
            User user = om.readValue(req.getReader(), User.class);
            System.out.println(user);
            //클라이언트 요청에서 username, password 추출
            String username = user.getUsername();
            String password = user.getPassword();

            System.out.println("유저네임: " + username);
            //스프링 시큐리티에서 username과 password를 검증하기 위해서는 token에 담아야 함
            UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password, null);

            return authenticationManager.authenticate(authToken);

        } catch (AuthenticationException e) {
            unsuccessfulAuthentication(req, res, e);
            return null;
        }
        catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    //로그인 성공시, jwt 토큰 만들어 반환
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) {

        CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();

        Long userId=userDetails.getId();
       String username=authentication.getName();

       Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
       Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
       GrantedAuthority auth=iterator.next();
       String role=auth.getAuthority();



       //토큰 생성
        String access=jwtUtil.createJwt("access", username, role, userId,600000L);
        String refresh=jwtUtil.createJwt("refresh", username, role, userId,86400000L);
        
        //refresh 토큰 저장
        addRefreshEntity(username, userId, refresh, 86400000L);

        //응답 설정
        response.setHeader("access", access);
        response.addCookie(createCookie("refresh", refresh));
        response.setStatus(HttpStatus.OK.value());

    }


    //로그인 실패시 거친다
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) {
        System.out.println("unsuccessfulAuthentication거침");
        //로그인 실패시 401 응답 코드 반환
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    }


    private Cookie createCookie(String key, String value){
        Cookie cookie=new Cookie(key,value);
        cookie.setMaxAge(24*60*60); //쿠키 유효시간
        //cookie.setSecure(true); //https 통신을 하는 경우 사용
        //cookie.setPath("/");  //쿠키가 적용될 범위
        cookie.setHttpOnly(true); //클라이언트에서 자바스크립트단으로 해당 쿠키 접귾하지 못하도록 막기

        return cookie;

    }
    
    private void addRefreshEntity(String username, Long userId, String refresh, Long expiredMs){
        Date date=new Date(System.currentTimeMillis()+expiredMs);
        
        Refresh refreshEntity=new Refresh();
        refreshEntity.setUsername(username);
        refreshEntity.setUser_id(userId);
        refreshEntity.setRefresh(refresh);
        refreshEntity.setExpiration(date.toString());
        
        refreshRepository.save(refreshEntity);
    }


}
