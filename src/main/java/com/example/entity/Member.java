package com.example.entity;

import java.util.Date;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;

import org.hibernate.annotations.UpdateTimestamp;
import org.springframework.format.annotation.DateTimeFormat;

import lombok.Data;

@Data
@Entity
@Table(name = "MEMBER")
public class Member {

    @Id
    @Column(name = "MID")
    private String mid;

    private String mname;
    private String mpw;
    private String mphone;
    private String memail;

    @DateTimeFormat(pattern = "yyyy-MM-dd HH:mm:ss.SSS")
    @UpdateTimestamp // 변경 시 날짜 정보 변경
    private Date mregdate;
}
