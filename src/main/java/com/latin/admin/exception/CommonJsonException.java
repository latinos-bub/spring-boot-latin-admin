package com.latin.admin.exception;

import com.alibaba.fastjson.JSONObject;
import com.latin.admin.enums.ErrorEnum;
import com.latin.admin.util.CommonUtils;

/**
 * @author: util.you.com@gmail.com
 * @date: 2019/7/29 15:49
 * @description: 封装 异常 类
 * @version: 1.0
 * @className: CommonJsonException
 * 在 校验参数时，如果不符合要求，可以跑出此错误类
 * 拦截器可以统一拦截此错误，将其中 JSON 返回给前端
 */
public class CommonJsonException extends RuntimeException{


    private JSONObject resultJson;



    /**
     * @author: util.you.com@gmail.com
     * @param: [errorEnum] 以 错误的 ErrorEnum 作参数
     * @return:
     * @date: 2019/7/29 15:54
     * @version: 1.0
     * @description:
     * 调用时可以在任何代码处直接 throws 这个 Exception，
     * 都会统一被拦截，并封装好 JSON 返回给前端
     */
    public CommonJsonException(ErrorEnum errorEnum){

        this.resultJson = CommonUtils.errorJson(errorEnum);
    }






    public CommonJsonException(JSONObject resultJson){

        this.resultJson = resultJson;
    }






    public JSONObject getResultJson(){

        return resultJson;
    }
}
