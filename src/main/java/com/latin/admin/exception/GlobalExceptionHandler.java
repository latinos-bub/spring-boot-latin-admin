package com.latin.admin.exception;

import com.alibaba.fastjson.JSONObject;
import com.latin.admin.enums.ErrorEnum;
import com.latin.admin.util.CommonUtils;
import org.apache.shiro.authz.UnauthenticatedException;
import org.apache.shiro.authz.UnauthorizedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.HttpServletRequest;

/**
 * @author: util.you.com@gmail.com
 * @date: 2019/7/29 17:41
 * @description: 全局异常拦截
 * @version: 1.0
 * @className: GlobalExceptionHandler
 */
@ControllerAdvice
@ResponseBody
public class GlobalExceptionHandler {


    // 引入 org.slf4j.Logger
    private Logger logger = LoggerFactory.getLogger(this.getClass().getName());



    @ExceptionHandler(value = Exception.class)
    public JSONObject defaultErrorHandler(HttpServletRequest request, Exception e){

        String errorPosition = "";
        // 如果错误堆栈信息存在
        if (e.getStackTrace().length > 0){
            StackTraceElement element = e.getStackTrace()[0];
            String fileName = element.getFileName() == null ? "未找到错误文件" : element.getFileName();
            int lineNumber = element.getLineNumber();
            errorPosition = fileName + " : " + lineNumber;
        }
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("code", ErrorEnum.E_400.getErrorCode());
        jsonObject.put("msg", ErrorEnum.E_400.getErrorMsg());

        JSONObject errorObject = new JSONObject();
        errorObject.put("errorLocation", e.toString() + " 错误位置: " + errorPosition);
        jsonObject.put("info", errorObject);
        logger.error("异常: ", e);

        return jsonObject;
    }






    /**
     * @author: util.you.com@gmail.com
     * @param: []
     * @return: com.alibaba.fastjson.JSONObject
     * @date: 2019/7/29 17:54
     * @version: 1.0
     * @description:
     * GET/POST 请求方法错误的拦截器
     * 因为开发时可能会发生，在进入 Controller 之前，上面的拦截器拦截不到这个错误
     * 因此定义了这个拦截器
     */
    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public JSONObject httpRequestMethodHandler(){

        return CommonUtils.errorJson(ErrorEnum.E_500);
    }







    /**
     * @author: util.you.com@gmail.com
     * @param: [commonJsonException]
     * @return: com.alibaba.fastjson.JSONObject
     * @date: 2019/7/29 18:00
     * @version: 1.0
     * @description: 本系统自定义的错误拦截器
     * 拦截到此错误后，就返回这个类里面的 JSON 给前端
     * 常见使用场景是 参数校验失败，抛出此错，返回错误信息给前端
     */
    @ExceptionHandler(CommonJsonException.class)
    public JSONObject commonJsonExceptionHandler(CommonJsonException commonJsonException){

        return commonJsonException.getResultJson();
    }







    /**
     * @author: util.you.com@gmail.com
     * @param: []
     * @return: com.alibaba.fastjson.JSONObject
     * @date: 2019/7/29 18:03
     * @version: 1.0
     * @description: 权限不足报错 拦截
     */
    @ExceptionHandler(UnauthorizedException.class)
    public JSONObject unauthorizedExceptionHandler(){

        return CommonUtils.errorJson(ErrorEnum.E_502);
    }







    /**
     * @author: util.you.com@gmail.com
     * @param: []
     * @return: com.alibaba.fastjson.JSONObject
     * @date: 2019/7/29 18:05
     * @version: 1.0
     * @description: 未登录报错拦截
     * 请求需要权限的接口，如果未登录就调用该接口，就会报该错误
     */
    @ExceptionHandler(UnauthenticatedException.class)
    public JSONObject unauthenticatedException(){

        return CommonUtils.errorJson(ErrorEnum.E_20011);
    }

}
