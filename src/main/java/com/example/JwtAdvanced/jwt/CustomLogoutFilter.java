package com.example.JwtAdvanced.jwt;

import com.example.JwtAdvanced.entity.Refresh;
import com.example.JwtAdvanced.redis.RefreshToken;
import com.example.JwtAdvanced.repository.RefreshRepository;
import com.example.JwtAdvanced.repository.RefreshTokenRepository;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.filter.GenericFilterBean;

import java.io.IOException;

public class CustomLogoutFilter extends GenericFilterBean {

    private final JWTUtil jwtUtil;
    //private final RefreshRepository refreshRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    public CustomLogoutFilter(JWTUtil jwtUtil, RefreshTokenRepository refreshTokenRepository) {
        this.jwtUtil = jwtUtil;
        this.refreshTokenRepository = refreshTokenRepository;
    }


    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {

        doFilter((HttpServletRequest)servletRequest, (HttpServletResponse)servletResponse,filterChain);
    }

    private void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException, ServletException {

        //path랑 메소드 확인
        String requestUri=request.getRequestURI();
        if(!requestUri.matches("^\\/logout$")){
            filterChain.doFilter(request, response);
            return;
        }
        String method=request.getMethod();
        if(!method.equals("POST")){
            filterChain.doFilter(request,response);
            return;
        }


        //refresh 토큰 얻기
        String refresh=null;
        Cookie[] cookies=request.getCookies();
        for(Cookie cookie:cookies){
            if(cookie.getName().equals("refresh")){
                refresh=cookie.getValue();
            }
        }

        //refresh가 null인지 체크
        if(refresh==null){
            filterChain.doFilter(request,response);
            return ;
        }

        //refresh 토큰 데이터베이스에 저장여부 체크
        RefreshToken refreshToken=refreshTokenRepository.findById(refresh).orElse(null);
        if(refreshToken==null){
            return;
        }
        //refresh 토큰 만료 여부 체크
        try{
            jwtUtil.isExpired(refresh);
        }catch(ExpiredJwtException e){
            return;
        }

        //토큰이 refresh인지 확인 (발급시 페이로드에 명시해놓음)
        String category=jwtUtil.getCategory(refresh);
        if(!category.equals("refresh")){
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        //로그아웃 진행
        //Refresh 토큰 DB에서 제거
        refreshTokenRepository.delete(refreshToken);

        //refresh 토큰 cookie값 null로 채워주기
        Cookie cookie=new Cookie("refresh", null);
        cookie.setMaxAge(0);
        cookie.setPath("/");

        response.addCookie(cookie);
        response.setStatus(HttpServletResponse.SC_OK);
    }




}
