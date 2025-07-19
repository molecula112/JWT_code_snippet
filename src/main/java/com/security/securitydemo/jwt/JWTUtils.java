package com.security.securitydemo.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Date;

// Ютильный класс который умеет парсить, валидировать и извлекать данные из JWT

@Component
public class JWTUtils {

    Logger logger = LoggerFactory.getLogger(JWTUtils.class);

    @Value("${spring.app.jwtSecret}")
    private String jwtSecret;

    @Value("${spring.app.jwtExpirationMs}")
    private int jwtExpirationMs;

    public String getJwtFromHeader(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        logger.debug("Authorization Header: {}", bearerToken);
        if(bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7); //Remove bearer prefix
        }
        return null;
    }

    public String parseJwt(HttpServletRequest request) {
        String jwt = getJwtFromHeader(request);
        logger.debug("JWT extracted!");
        return jwt;
    }

    public String generateTokenFromUsername(UserDetails useDetails) {
        String username = useDetails.getUsername();
        return Jwts.builder()
                .subject(username)
                .issuedAt(new Date())
                .expiration(new Date((new Date()).getTime() + jwtExpirationMs))
                .signWith(key())
                .compact();
    }

    public String getUserNameFromJwtToken(String token) {
        return Jwts.parser()
                .verifyWith((SecretKey) key()) // Указываем, каким секретным ключом нужно проверять подпись токена. Метод key() возвращает SecretKey.
                .build() // Завершаем конфигурацию парсера — создаётся JwtParser.
                .parseSignedClaims(token) // Парсим токен и проверяем: 1) Проверяется подпись токена (если подпись неверна — будет выброшено исключение) 2)Извлекаются claims (полезная нагрузка JWT).
                .getPayload() // Получаем тело токена (claims) — структуру с данными, вроде sub, exp, roles, и т.д.
                .getSubject(); // Возвращаем значение sub (subject) — обычно это имя пользователя или его ID.
    }

    public boolean validateJwtToken(String authToken) {
        try {
            System.out.println("Validate");
            Jwts.parser()
                    .verifyWith((SecretKey) key()) // Указываем секретный ключ, чтобы проверить подпись токена
                    .build()
                    .parseSignedClaims(authToken); // Пытаемся распарсить и верифицировать токен
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    private Key key() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
    }

}
