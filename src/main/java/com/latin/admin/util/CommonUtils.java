package com.latin.admin.util;

import com.alibaba.fastjson.JSONObject;
import com.latin.admin.enums.ErrorEnum;
import com.latin.admin.exception.CommonJsonException;

import javax.servlet.http.HttpServletRequest;
import java.util.Enumeration;
import java.util.List;

/**
 * @author: util.you.com@gmail.com
 * @date: 2019/7/29 14:54
 * @description: json 工具类
 * @version: 1.0
 * @className: CommonUtils
 */
public class CommonUtils {



    /**
     * @author: util.you.com@gmail.com
     * @param: []
     * @return: com.alibaba.fastjson.JSONObject
     * @date: 2019/7/29 14:55
     * @version: 1.0
     * @description: 返回一个 info 为空对象的成功消息的 JSON
     */
    public static JSONObject successJson(){

        return successJson(new JSONObject());
    }





    /**
     * @author: util.you.com@gmail.com
     * @param: [info]
     * @return: com.alibaba.fastjson.JSONObject
     * @date: 2019/7/29 15:02
     * @version: 1.0
     * @description: 返回一个 返回码 为 100 的 JSON
     */
    public static JSONObject successJson(Object info){

        JSONObject jsonObject = new JSONObject();
        jsonObject.put("code", ConstantUtils.SUCCESS_CODE);
        jsonObject.put("msg", ConstantUtils.SUCCESS_MSG);
        jsonObject.put("info", info);

        return jsonObject;
    }







    /**
     * @author: util.you.com@gmail.com
     * @param: [errorEnum]
     * @return: com.alibaba.fastjson.JSONObject
     * @date: 2019/7/29 15:14
     * @version: 1.0
     * @description: 返回错误信息 JSON
     */
    public static JSONObject errorJson(ErrorEnum errorEnum){

        JSONObject resultJson = new JSONObject();
        resultJson.put("code", errorEnum.getErrorCode());
        resultJson.put("msg", errorEnum.getErrorMsg());
        resultJson.put("info", new JSONObject());
        return resultJson;
    }







    /**
     * @author: util.you.com@gmail.com
     * @param: [requestJson, list, totalCount]
     * @return: com.alibaba.fastjson.JSONObject
     * @date: 2019/7/29 15:18
     * @version: 1.0
     * @description:
     *  requestJson: 请求参数 json, 此 json 在之前调用 fillPageParam 方法时， 已经将 pageRow 放入
     *  list: 查询分页对象 list
     *  totalCount: 查询出记录的总条数
     */
    public static JSONObject successPage(final JSONObject requestJson,
                                         List<JSONObject> list,
                                         int totalCount){

        int pageRow = requestJson.getIntValue("pageRow");
        int totalPage = getPageCounts(pageRow, totalCount);

        JSONObject result = successJson();
        JSONObject info = new JSONObject();
        info.put("list", list);
        info.put("totalCount", totalCount);
        info.put("totalPage", totalPage);
        result.put("info", info);

        return result;
    }







    /**
     * @author: util.you.com@gmail.com
     * @param: [list] 查询分页对象 list
     * @return: com.alibaba.fastjson.JSONObject
     * @date: 2019/7/29 15:23
     * @version: 1.0
     * @description: 查询分页结果后的封装工具方法
     */
    public static JSONObject successPage(List<JSONObject> list){

        JSONObject jsonObject = successJson();
        JSONObject info = new JSONObject();
        info.put("list", list);
        jsonObject.put("info", info);

        return jsonObject;
    }







    /**
     * @author: util.you.com@gmail.com
     * @param: [pageRow, totalCount] 每页行数 | 结果的总条数
     * @return: int
     * @date: 2019/7/29 15:25
     * @version: 1.0
     * @description: 获取 总页数
     */
    private static int getPageCounts(int pageRow, int totalCount){

        if (totalCount == 0){
            return 1;
        }
        return totalCount % pageRow > 0 ?
                totalCount / pageRow + 1 :
                totalCount / pageRow;
    }






    /**
     * @author: util.you.com@gmail.com
     * @param: [request]
     * @return: com.alibaba.fastjson.JSONObject
     * @date: 2019/7/29 15:29
     * @version: 1.0
     * @description: 将 request 参数值 转为 JSON
     */
    public static JSONObject request2Json(HttpServletRequest request){

        JSONObject requestJson = new JSONObject();
        Enumeration paramNames = request.getParameterNames();
        while (paramNames.hasMoreElements()){
            String paramName = (String) paramNames.nextElement();
            String[] paramValues = request.getParameterValues(paramName);
            StringBuilder stringBuilder = new StringBuilder();
            for (int i = 0; i < paramValues.length; i++){
                if (paramValues[i].length() > 0){
                    if (i > 0){
                        stringBuilder.append(",");
                    }
                    stringBuilder.append(paramValues[i]);
                }
            }
            requestJson.put(paramName, stringBuilder.toString());
        }

        return requestJson;
    }







    /**
     * @author: util.you.com@gmail.com
     * @param: []
     * @return: com.alibaba.fastjson.JSONObject
     * @date: 2019/7/29 15:37
     * @version: 1.0
     * @description: 将 request 转 JSON 并且验证非空字段
     */
    public static JSONObject convert2JsonAndCheckRequiredColumns(
            HttpServletRequest request,
            String requiredColumns
    ){

        JSONObject jsonObject = request2Json(request);
        hasAllRequired(jsonObject, requiredColumns);

        return jsonObject;
    }







    /**
     * @author: util.you.com@gmail.com
     * @param: [jsonObject, requiredColumns] 必填的参数名称字段 逗号隔开
     * @return: void
     * @date: 2019/7/29 15:40
     * @version: 1.0
     * @description: 验证是否有全部必填字段
     */
    public static void hasAllRequired(final JSONObject jsonObject,
                                      String requiredColumns){

        if (!StringUtils.isNullOrEmpty(requiredColumns)){
            // 验证字段非空
            String[] columns = requiredColumns.split(",");
            String missCol = "";
            for (String column : columns){
                Object obj = jsonObject.get(column.trim());
                if (StringUtils.isNullOrEmpty(obj)){
                    missCol += column + "  ";
                }
            }

            if (!StringUtils.isNullOrEmpty(missCol)){
                jsonObject.clear();
                jsonObject.put("code", ErrorEnum.E_90003.getErrorCode());
                jsonObject.put("msg", "缺少必填参数: " + missCol.trim());
                jsonObject.put("info", new JSONObject());
                throw new CommonJsonException(jsonObject);
            }
        }
    }








    /**
     * @author: util.you.com@gmail.com
     * @param: [paramObject, defaultPageRow] 查询条件 JSON | 默认的每页条数，即前端不传 pageRow 参数时的每页条数
     * @return: void
     * @date: 2019/7/29 15:58
     * @version: 1.0
     * @description: 在分页查询之前，为查询条件里加上分页参数
     */
    private static void fillPageParam(final JSONObject paramObject,
                                      int defaultPageRow){

        int pageNum = paramObject.getIntValue("pageNum");
        pageNum = pageNum == 0 ? 1 : pageNum;
        int pageRow = paramObject.getIntValue("pageRow");
        pageRow = pageRow == 0 ? defaultPageRow : pageRow;
        paramObject.put("offset", (pageNum - 1) * pageRow);
        paramObject.put("pageRow", pageRow);
        paramObject.put("pageNum", pageNum);

        // 删除此参数，防止前端传了这个参数，pageHelper 分页插件检测到之后，拦截导致 sql 错误
        paramObject.remove("pageSize");
    }







    /**
     * @author: util.you.com@gmail.com
     * @param: [paramObject]
     * @return: void
     * @date: 2019/7/29 16:06
     * @version: 1.0
     * @description: 分页查询之前的处理参数
     * 没有传 pageRow 参数时，默认每页 10 条
     */
    public static void fillPageParam(final JSONObject paramObject){

        fillPageParam(paramObject, 10);
    }


}
