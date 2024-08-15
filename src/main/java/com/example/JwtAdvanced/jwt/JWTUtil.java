package com.example.JwtAdvanced.jwt;

import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Date;

//jwt 검증, 발급
@Component
public class JWTUtil {

    private SecretKey secretKey;

    //application.properties에 저장한 암호화 키를 불러와 이를 바탕으로 객체 키 생성해준다
    public JWTUtil(@Value("${spring.jwt.secret}")String secret){
        this.secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), Jwts.SIG.HS256.key().build().getAlgorithm());
    }

    //토큰 검증
    public String getUsername(String token) {

        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("username", String.class);
    }

    public String getRole(String token) {

        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("role", String.class);
    }

    public String getCategory(String token){
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("category", String.class);
    }

    public Boolean isExpired(String token) { //토큰이 만료되었는지 검사

        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().getExpiration().before(new Date());
    }

    //토큰 생성(로그인 성공시)
    public String createJwt(String category, String username, String role, Long userId,Long expiredMs){
        return Jwts.builder()
                .claim("category",category)
                .claim("username",username)
                .claim("role",role)
                .claim("user_id",userId)
                .issuedAt(new Date(System.currentTimeMillis())) //토큰 생성시간
                .expiration(new Date(System.currentTimeMillis()+expiredMs)) //토큰만료시간
                .signWith(secretKey) //암호화
                .compact();
    }
}
