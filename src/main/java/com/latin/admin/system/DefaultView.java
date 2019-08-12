package com.latin.admin.system;

import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

/**
 * @author: util.you.com@gmail.com
 * @date: 2019/7/30 10:50
 * @description: 设置首页
 * @version: 1.0
 * @className: DefaultView
 */
@Configuration
public class DefaultView extends WebMvcConfigurerAdapter {




    @Override
    public void addViewControllers(ViewControllerRegistry registry){

        registry.addViewController("/").setViewName("forward:/index.html");
        registry.setOrder(Ordered.HIGHEST_PRECEDENCE);
        super.addViewControllers(registry);
    }
}
