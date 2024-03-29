package com.example.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.example.entity.Member;
import java.util.List;


@Repository
public interface MemberRepository extends JpaRepository<Member, String>{
    
    Member findByMid(String mid);
}
