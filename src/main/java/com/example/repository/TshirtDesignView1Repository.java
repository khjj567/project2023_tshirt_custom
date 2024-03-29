package com.example.repository;

import java.math.BigInteger;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.example.entity.TshirtDesignView1;

@Repository
public interface TshirtDesignView1Repository extends JpaRepository<TshirtDesignView1, BigInteger>{
    
    // 사이즈, 프린팅방식, 수량(한계 필요), 색깔, 
    // 프린팅사이드
    
}
