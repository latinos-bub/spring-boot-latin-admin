package com.latin.admin.shiro;

import com.alibaba.fastjson.JSONObject;
import com.latin.admin.enums.ErrorEnum;
import org.apache.shiro.web.filter.authc.FormAuthenticationFilter;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;
import java.io.PrintWriter;

/**
 * @author: util.you.com@gmail.com
 * @date: 2019/7/29 16:20
 * @description:
 * @version: 1.0
 * @className: AjaxPermissionsAuthorizationFilter
 * 对没有登录的请求进行拦截，全部返回 JSON 信息，
 * 覆盖掉 Shiro 原本的 跳转 login.jsp 的拦截方式
 */
public class AjaxPermissionsAuthorizationFilter extends FormAuthenticationFilter {





    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response){

        JSONObject jsonObject = new JSONObject();
        jsonObject.put("code", ErrorEnum.E_20011.getErrorCode());
        jsonObject.put("msg", ErrorEnum.E_20011.getErrorMsg());
        PrintWriter out = null;
        HttpServletResponse res = (HttpServletResponse) response;
        try {
            res.setCharacterEncoding("UTF-8");
            res.setContentType("application/json");
            out = response.getWriter();
            out.println(jsonObject);
        }catch (Exception e){
            System.out.println(e.getMessage());
        }finally {
            if (null != out) out.flush(); out.close();
        }

        return false;
    }






    @Bean
    public FilterRegistrationBean registration(AjaxPermissionsAuthorizationFilter filter){

        FilterRegistrationBean registrationBean = new FilterRegistrationBean(filter);
        registrationBean.setEnabled(false);

        return registrationBean;
    }
}
