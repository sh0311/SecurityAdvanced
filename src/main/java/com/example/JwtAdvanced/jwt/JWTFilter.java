package com.example.JwtAdvanced.jwt;

import com.example.JwtAdvanced.dto.CustomUserDetails;
import com.example.JwtAdvanced.entity.User;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.io.PrintWriter;

//헤더(Authorization)에 들어있는 토큰을 꺼내 이상이 없는 경우 SecurityContextHolder에 저장하게 된다
//요청에 대해 한번만 동작하는 필터 (모든 경로에 대해 request 요청시 동작)
public class JWTFilter extends OncePerRequestFilter {
    //JWTUtil에서 검증할 메소드 가져와야 하므로 의존성 주입
    private final JWTUtil jwtUtil;
    public JWTFilter(JWTUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        String requestURI=request.getRequestURI();
        if("/login".equals(requestURI)){
            filterChain.doFilter(request, response);
            return;
        }

        //헤더에서 access 키에 담긴 토큰을 꺼냄
        String accessToken=request.getHeader("access");

        //토큰이 없다면 더이상 밑에 작업 처리 하지 않고 다음 필터로 넘김
        if(accessToken==null){
            filterChain.doFilter(request, response);
            return;
        }

        //토큰이 있다면 토큰 만료여부 확인, 만료시 다음 필터로 넘기지 않고 만료되었음을 response
        try{
            jwtUtil.isExpired(accessToken);
        }catch(ExpiredJwtException e){
            //response body
            PrintWriter writer=response.getWriter();
            writer.print("access token expired");

            //response status code
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        String username=jwtUtil.getUsername(accessToken);
        String role=jwtUtil.getRole(accessToken);

        User userEntity=new User();
        userEntity.setUsername(username);
        userEntity.setRole(role);
        CustomUserDetails userDetails = new CustomUserDetails(userEntity);

        Authentication authToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(authToken);

        filterChain.doFilter(request, response);

    }
}
