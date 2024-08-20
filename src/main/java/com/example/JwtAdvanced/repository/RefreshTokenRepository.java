package com.example.JwtAdvanced.repository;

import com.example.JwtAdvanced.redis.RefreshToken;
import org.springframework.data.repository.CrudRepository;

public interface RefreshTokenRepository extends CrudRepository<RefreshToken, String> {
}
