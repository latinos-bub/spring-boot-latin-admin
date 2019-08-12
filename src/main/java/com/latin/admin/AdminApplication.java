package com.latin.admin;


import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;

/**
 * @author: util.youl.com@gmail.com
 * @date: 2019/7/27 18:39
 * @description: spring boot 入口类
 * @version: 1.0
 * @className: AdminApplication
 */
@SpringBootApplication
@MapperScan("com.latin.admin.dao")
public class AdminApplication extends SpringBootServletInitializer {


    public static void main(String[] args) {

        SpringApplication springApplication = new SpringApplication(AdminApplication.class);
        springApplication.run(args);
    }




    @Override
    protected SpringApplicationBuilder configure(SpringApplicationBuilder builder){

        // 注意这里要指向原先用 mian 方法执行的 Application 启动类
        return builder.sources(AdminApplication.class);
    }
}
