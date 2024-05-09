package com.mli.signature;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;

@MapperScan("com.mli.signature.module.signature.dao")
@ComponentScan(basePackages = "com.mli.signature")
@SpringBootApplication
public class ApiSpringBoot2Application {
	public static void main(String[] args) {
		SpringApplication.run(ApiSpringBoot2Application.class, args);
	}

}
