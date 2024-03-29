package com.example.entity;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.OneToMany;
import javax.persistence.SequenceGenerator;
import javax.persistence.Table;

import lombok.Data;
import lombok.ToString;

@Data
@Entity
@Table(name = "PRINTINGSIDE")
@SequenceGenerator(name = "SEQ_PSIDE_NO", sequenceName = "SEQ_PSIDE_NO", initialValue = 1, allocationSize = 1)
public class PrintingSide {
    
    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "SEQ_PSIDE_NO")
    @Column(name="PSNO")
    private BigInteger psno;
    private String psidename;

    // PSNO가 PsidePic에 외래키로 들어감
    @ToString.Exclude
    @OneToMany(mappedBy = "printingSide", cascade=CascadeType.REMOVE, fetch=FetchType.LAZY)
    private List<PsidePic> list = new ArrayList<>();

    @ToString.Exclude
    @OneToMany(mappedBy = "printingSide", cascade=CascadeType.REMOVE, fetch=FetchType.LAZY)
    private List<DesignOne> list4 = new ArrayList<>();
}   

