package com.example.JwtAdvanced.redis;


import lombok.Getter;
import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;

@Getter
@RedisHash(value="refreshToken", timeToLive=86400)
public class RefreshToken {

    @Id
    private String refreshToken;  //value
    private Long userId;

    public RefreshToken(String refreshToken, Long userId){
        this.refreshToken = refreshToken;
        this.userId = userId;
    }
}

