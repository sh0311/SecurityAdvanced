package com.example.JwtAdvanced.service;

import com.example.JwtAdvanced.dto.CustomUserDetails;
import com.example.JwtAdvanced.entity.Refresh;
import com.example.JwtAdvanced.jwt.JWTUtil;
import com.example.JwtAdvanced.repository.RefreshRepository;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.autoconfigure.data.redis.RedisProperties;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.util.Date;

@Service
public class ReissueService {
    private final JWTUtil jwtUtil;
    private final RefreshRepository refreshRepository;

    public ReissueService(JWTUtil jwtUtil, RefreshRepository refreshRepository) {
        this.jwtUtil = jwtUtil;
        this.refreshRepository = refreshRepository;
    }

    public ResponseEntity<String> reissue(HttpServletRequest request, HttpServletResponse response) {

        //refresh 토큰 얻기
        String refresh=null;

        Cookie[] cookies=request.getCookies();
        for(Cookie cookie:cookies){
            if(cookie.getName().equals("refresh")){
                refresh=cookie.getValue();
            }
        }

        //refresh 토큰 존재여부 체크
        if(refresh==null){
            return ResponseEntity.badRequest().body("Refresh token is empty");
        }

        //refresh 토큰 만료여부 체크
        try{
            jwtUtil.isExpired(refresh);
        }catch(ExpiredJwtException e){
            return ResponseEntity.badRequest().body("refresh token expired");
        }

        //토큰이 refresh인지 확인(발급시 페이로드에 명시)
        String category=jwtUtil.getCategory(refresh);
        if(!category.equals("refresh")){
            return ResponseEntity.badRequest().body("invalid refresh token");
        }

        //refresh 토큰이 정상이라면
        String username=jwtUtil.getUsername(refresh);
        String role=jwtUtil.getRole(refresh);
        Long userId=jwtUtil.getUserId(refresh);

        //새 JWT토큰 생성
        String newJwt=jwtUtil.createJwt("access",username, role, userId, 600000L);
        String newRefresh=jwtUtil.createJwt("refresh", username, role,userId, 86400000L);

        refreshRepository.deleteByRefresh(refresh);
        addRefreshEntity(username,userId,newRefresh, 8640000L);

        //response
        response.setHeader("access", newJwt);
        response.addCookie(createCookie("refresh", newRefresh));

        return ResponseEntity.ok("새 access 토큰 발급");

    }


    private Cookie createCookie(String key,String value){
        Cookie cookie=new Cookie(key,value);
        cookie.setMaxAge(24*60*60);
        //cookie.setSecure(true);
        //cookie.setPath("/");
        cookie.setHttpOnly(true);

        return cookie;
    }

    private void addRefreshEntity(String username,Long userId,String newRefresh,Long expiredMs){
        Date date = new Date(System.currentTimeMillis() + expiredMs);

        Refresh refresh=new Refresh();
        refresh.setUsername(username);
        refresh.setUser_id(userId);
        refresh.setRefresh(newRefresh);
        refresh.setExpiration(date.toString());

        refreshRepository.save(refresh);
    }
}

