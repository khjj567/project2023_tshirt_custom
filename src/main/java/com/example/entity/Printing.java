package com.example.entity;

import java.math.BigInteger;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.SequenceGenerator;
import javax.persistence.Table;

import lombok.Data;

@Data
@Entity
@Table(name = "PRINTING")
@SequenceGenerator(name = "SEQ_PRINTING_NO", sequenceName = "SEQ_PRINTING_NO", initialValue = 6, allocationSize = 1)
public class Printing {
    // 에러
    //Error creating bean with name 'entityManagerFactory' defined in class path resource [org/springframework/boot/autoconfigure/orm/jpa/HibernateJpaConfiguration.class]: Invocation of init method failed; nested exception is javax.persistence.PersistenceException: [PersistenceUnit: default] Unable to build Hibernate SessionFactory; nested exception is org.hibernate.tool.schema.spi.SchemaManagementException: Export identifier [seq_printing_no] encountered more than once
    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "SEQ_PRINTING_NO")
    @Column(name="PNO")
    private BigInteger pno;
    private BigInteger pprice;
    private String pmethod;
}   

