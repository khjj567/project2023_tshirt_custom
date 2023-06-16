package com.example.restcontroller;

import java.util.HashMap;
import java.util.Map;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.dto.MemberUser;
import com.example.entity.Member;
import com.example.repository.MemberRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RestController
@RequestMapping(value = "/api/member")
@RequiredArgsConstructor
@Slf4j
public class RestMemberController {
    final JwtUtil jwtUtil; // Component 객체 생성
    final BCryptPasswordEncoder bcpe = new BCryptPasswordEncoder(); // 객체 생성
    final MemberRepository mRepository;

    //127.0.0.1:9090/CUSTOM/api/member/login.json
    @PostMapping(value="/login.json")
    public Map<String, Object> loginPOST(@RequestBody Member member) {
    Map<String, Object> retMap = new HashMap<>();
        try {
            // 1. 이메일, 암호 전송 확인
            
            // 2. 이메일을 이용해서 정보를 가져옴.
            Member retmember = mRepository.findById(member.getMid()).orElse(null);
            log.info("회원정보 => {}", retmember.toString());
            // // 3. 실패시 전송할 데이터
            // retMap.put( "status", 0 );

            // // 4. 암호가 일치하는지 확인 => 전송된 hash되지 않은 암호와 DB에 해시된 암호 일치 확인
            // if(  bcpe.matches( member.getMpw(), retmember.getMpw()) ) {
                retMap.put( "status", 200 );
                retMap.put( "token", jwtUtil.createJwt(retmember.getMid(), retmember.getMname() ) );

                //  암호가 일치하고 로그인요건을 충족하면 200과 토큰(jwtUtil이 )
            
            // } 

        } catch (Exception e) {
            e.printStackTrace(); 
            retMap.put( "status", -1 );
            retMap.put( "error", e.getMessage() );
        }
        return retMap;
    }
    
    //127.0.0.1:9090/CUSTOM/api/member/withdraw.json
    @PostMapping(value="/withdraw.json")
    public Map<String, Object> withdrawPOST(
        @RequestBody Map<String, Object> map
        // @RequestHeader(name ="token") String token
        // @RequestBody Member member
        ) {
    Map<String, Object> retMap = new HashMap<>();
        try {
            
            log.info("MAP => {}", map);
            Member member = mRepository.findByMid((String)map.get("mid"));
            log.info("사용자 => {}", member);

                if(bcpe.matches((String)map.get("mpw"), member.getMpw())){
                    member.setMemail(null);
                    member.setMname(null);
                    member.setMphone(null);
                    member.setMpw(null);
                    member.setMregdate(null);

                    mRepository.save(member);

                    retMap.put( "status", 200 );
                    retMap.put( "ret", -1 );
                }

        } catch (Exception e) {
            e.printStackTrace(); 
            retMap.put( "status", -1 );
            retMap.put( "error", e.getMessage() );
        }
        return retMap;
    }
}
