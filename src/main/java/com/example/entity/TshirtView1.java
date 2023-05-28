package com.example.entity;

import java.math.BigInteger;

import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Lob;
import javax.persistence.Table;

import org.springframework.data.annotation.Immutable;

import lombok.Data;
import lombok.ToString;

@Data
@Immutable // VIEW entity 만들땐 필수 어노테이션
@Entity
@Table(name = "TSHIRTVIEW1")
public class TshirtView1 {

    @Id
    private BigInteger tno;

    private String tname;
    private BigInteger tprice;

    private BigInteger tquantity;
    //

    private BigInteger ttno;
    private String ttname;

    //
    private	BigInteger	ino	;
    private	String	iname	;
    private	BigInteger	isize	;
    @Lob
    @ToString.Exclude
    private	byte[]	idata	;
    private	String	itype	;
 
    
}
