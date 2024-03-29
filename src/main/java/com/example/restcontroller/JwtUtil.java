package com.example.restcontroller;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import org.springframework.stereotype.Component;

import com.example.entity.Member;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Component
public class JwtUtil {
    private final String BASEKEY = "figyutyujkjwnt125614bejwp[cmds;s[mvsjlvyutyutyutyuyut7y3_fejknfej!!!";
    
    // 토큰생성하는 메소드
    public String createJwt( String id, String name ) throws Exception {
        // 여기서 말하는  id와 name이 무엇인지

        // 1. header정보
        Map<String, Object> headerMap = new HashMap<>();
        headerMap.put("typ","JWT"); //타입
        headerMap.put("alg", "HS256"); // hash알고리즘

        // 2. 토큰에 포함시킬 사용자 정보들..
        Map<String, Object> claimsMap = new HashMap<>();
        claimsMap.put("id", id);   // 아이디
        claimsMap.put("name", name); // 이름

        // 3. 토큰의 만료시간 ex) 2시간 => 현재시간 + 1000 * 60 * 60 * 2
        Date expiredTime = new Date();
        expiredTime.setTime( expiredTime.getTime() + 1000 * 60 * 60 * 3 );

        // 4. 키 발행
        byte[] keyBytes = DatatypeConverter.parseBase64Binary(BASEKEY);
        Key signKey = new SecretKeySpec(keyBytes, SignatureAlgorithm.HS256.getJcaName());

        // 1 ~ 4의 정보를 이용해서 토큰 생성
        JwtBuilder builder = Jwts.builder()
            .setHeader(headerMap)
            .setClaims(claimsMap)
            .setSubject("TEST")
            .setExpiration(expiredTime)
            .signWith(signKey, SignatureAlgorithm.HS256);
        
        // 토큰을 String 타입으로 변환
        return builder.compact();
    }

    // 토큰에 대해서 검증하고 데이터를 추출하는 메소드
    public Member checkJwt(String token) throws Exception{
        // public boolean -> public Student2 (토큰에 있는 이메일을 받아오기 위해서)
        try {
            // 1. key 준비
            byte[] keyBytes = DatatypeConverter.parseBase64Binary(BASEKEY);

            Claims claims = Jwts.parserBuilder()
                .setSigningKey(keyBytes)
                .build()
                .parseClaimsJws(token)
                .getBody();
            Member obj = new Member();
        obj.setMid((String) claims.get("id"));
        obj.setMname((String) claims.get("name"));
            System.out.println( "추출한 아이디 => " + claims.get("id"));    
            System.out.println( "추출한 이름   => " + claims.get("name"));    
            return obj;
        } 
        catch(ExpiredJwtException e1) {
            System.err.println("만료시간 종료" + e1.getMessage());
            return null;
        }
        catch(JwtException e2) {
            System.err.println("토큰오류" + e2.getMessage());
            return null;
        }
        catch(Exception e) {
            System.out.println("e1과 e2 오류 아닌 모든 오류" + e.getMessage());
            return null;
        }
    }
}
