package com.topsoft.action.login;

import auth.AuthenticationRemotService;
import auth.AuthenticationRemotServiceService;
import cfca.etl.common.client.exception.ClientException;
import cfca.etl.uaclient.UAClient;
import cfca.etl.uaserver.vo.request.AuthenticateVO;
import cfca.etl.uaserver.vo.response.SubscriberVO;
import cfca.sadk.lib.crypto.JCrypto;
import cfca.sadk.lib.crypto.Session;
import cfca.sadk.util.Signature;
import com.alipay.api.AlipayApiException;
import com.alipay.api.AlipayClient;
import com.alipay.api.DefaultAlipayClient;
import com.alipay.api.domain.ZhimaCustomerCertificationCertifyModel;
import com.alipay.api.domain.ZhimaCustomerCertificationInitializeModel;
import com.alipay.api.request.ZhimaCustomerCertificationCertifyRequest;
import com.alipay.api.request.ZhimaCustomerCertificationInitializeRequest;
import com.alipay.api.request.ZhimaCustomerCertificationQueryRequest;
import com.alipay.api.response.ZhimaCustomerCertificationCertifyResponse;
import com.alipay.api.response.ZhimaCustomerCertificationInitializeResponse;
import com.alipay.api.response.ZhimaCustomerCertificationQueryResponse;
import com.csii.hk.sign.CheckSignData;
import com.google.common.base.Strings;
import com.server.ASN1Util;
import com.topsoft.entity.*;
import com.topsoft.exception.LoginException;
import com.topsoft.service.*;
import com.topsoft.util.*;
import net.sf.json.JSONArray;
import net.sf.json.JSONException;
import net.sf.json.JSONObject;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang3.StringEscapeUtils;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.util.EntityUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.multipart.MultipartHttpServletRequest;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLDecoder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;

/**
 * 注册登录相关的类
 *
 * @author huyanliang 
 */
@Component
@RequestMapping("/login")
public class LoginAction {
    @Autowired
    private MessageService mesgService;
    @Autowired
    private EntUserService entUserService = null;
    @Autowired
    private BusiMainBodyInfoService busiMainBodyInfoService = null;
    @Autowired
    private CodeTableService codeService;
    @Autowired
    private BusService busService;
    @Autowired
	private DatumManagerService service;
    @Autowired
    private DatumManagerService datumService;
    @Autowired
    private LepAndMarInfoService lepAndMarInfoService;

    @Autowired
    private AdminService adminService;
    
//    @Autowired
//    private NamePreApproveService namePreApproveService;

//	@RequestMapping("/login.action")
//	public String login(HttpServletRequest request,
//			HttpServletResponse response, ModelMap model) {
//		model.put("location", "用户登录");
//		String cookieValue = CookieUtil.readCookie(request, response);
//		if (cookieValue.equals(CookieUtil.COOKIE_NULL)) {
//			// 没有记住密码
//
//		} else if (cookieValue.equals(CookieUtil.COOKIE_ILLEGAL)) {
//			// 不合法登录
//
//		} else if (cookieValue.equals(CookieUtil.COOKIE_INVALID)) {
//			// cookie失效
//
//		} else {
//			String[] s = cookieValue.split("_");
//			request.setAttribute("username", s[0]);
//			request.setAttribute("password", s[1]);
//			request.setAttribute("remPwd", "true");
//		}
//		return "/template/login/login.html";
//	}

    /**
     * 判断用户名密码是否匹配
     * 陈迪--添加用户名密码校验
     * @return
     */
    @RequestMapping("/checkUser.action")
    @ResponseBody
    public Map<String,String> checkUser(HttpServletRequest request){
        Map<String,String> result = new HashMap<String,String>();
        String userName = request.getParameter("username");
        String passWord = request.getParameter("password");
        boolean phoneLoginFlag=codeService.getSysParameterAsBoolean(SysConstants.PHONELOGINFLAG);
        EntUser entUser = entUserService.findByUsername(userName,phoneLoginFlag);
        if(entUser != null && MD5Util.checkPasswordMD5(passWord, entUser.getPassword())){
            result.put("success","true");
        }else{
            result.put("success","false");
        }
        return result; 
    }

    @RequestMapping("/checkLogin.action")
    public String checkLogin(HttpServletRequest request,
                             HttpServletResponse response, ModelMap model) throws LoginException, UnsupportedEncodingException, IOException, ParseException {
//        boolean isOutRegisterAndCancel = codeService.getSysParameterAsBoolean(SysConstants.isOutRegisterAndCancel);
    	String info = "";
        HttpSession session = request.getSession();
        String userName = request.getParameter("username2");
        String passWord = request.getParameter("password2");
        if(userName==null || "".equals(userName)){
        	return "forward:/index.action";
        }
        //region 杨志，20170308，合肥拓普 公众服务平台需求（12），DEV00202369，添加获取loginWay=5的账户密码
//        String info = "";
        
        BASE64Decoder decoder = new BASE64Decoder();
        userName = new String(decoder.decodeBuffer(userName),"utf-8");
        passWord = new String(decoder.decodeBuffer(passWord),"utf-8");
        Calendar c = Calendar.getInstance();
        c.setTime(new Date());
        c.set(Calendar.HOUR_OF_DAY, 0);
        c.set(Calendar.MINUTE, 0);
        c.set(Calendar.SECOND, 0);
        c.set(Calendar.MILLISECOND, 0);
        String time = c.getTimeInMillis() + "";
        passWord=passWord.replace(time, "");
        String remPwd = request.getParameter("remPwd");
//        String type = request.getParameter("type");
        boolean phoneLoginFlag=codeService.getSysParameterAsBoolean(SysConstants.PHONELOGINFLAG);
        EntUser entUser = entUserService.findByUsername(userName,phoneLoginFlag);
        if ("4".equals(codeService.getSysParameter(SysConstants.loginWay))){
            if (entUserService.findByUsername(userName,phoneLoginFlag) == null) {
                entUser = entUserService.findByTel(userName);
            }
        }

        if (entUser != null && MD5Util.checkPasswordMD5(passWord, entUser.getPassword())&&!EntUser.USERFROM_MEIMS.equals(entUser.getUserFrom())) {
            //region 杨志，20170308，合肥拓普 公众服务平台需求（12），DEV00202369，添加手机短信验证
            EntUser oldEntUser = (EntUser)session.getAttribute("entUser");
            if(oldEntUser!=null&&oldEntUser.getId()!=null&&!oldEntUser.getId().equals(entUser.getId())){
            	session.removeAttribute("entUser");
            }
            if (entUser.getThisTime()==null) {
            	entUser.setLastTime(new Date());
            } else {
            	entUser.setLastTime(entUser.getThisTime());
            }
            entUser.setThisTime(new Date());
            session.setAttribute("entUser", entUser);
            entUserService.update(entUser);
            if (remPwd != null && remPwd.equals("true")) {
                CookieUtil.saveCookie(userName, passWord, response);
            } else {
                CookieUtil.clearCookie(response);
            }
            session.setAttribute("ToTopmeims", "N");
            
            //删除实名认证提示标识
            request.getSession().removeAttribute("realNameTipFlag");
          //如果配置了用户中心，登陆时优先进入用户中心
        	if(codeService.getSysParameterAsBoolean(SysConstants.USERCENTER)){
        		 return "redirect:/toUserCenter.action";
        	}
            BusiMainBodyInfo info1 = busiMainBodyInfoService.findBusiMainBodyInfoByUserIdAndBusiType(
                    entUser.getId(), BusiMainBodyInfo.BUSITYPE_MC);
            BusiMainBodyInfo info2 = busiMainBodyInfoService.findBusiMainBodyInfoByUserIdAndBusiType(
                    entUser.getId(), BusiMainBodyInfo.BUSITYPE_SL);
            if (info2 != null && info2.getId() != null) {//进入设立流程图
                return "redirect:/flowChoices.action?busType=02&busiId=" + info2.getId();
            } else if (info1 != null && info1.getId() != null) {//进入名称流程图
                return "redirect:/flowChoices.action?busType=01&busiId=" + info1.getId();
            }
            return "redirect:/toUserCenter.action";//业务引导
        } else if (entUser == null||!MD5Util.checkPasswordMD5(passWord, entUser.getPassword())) {
            model.addAttribute("msg", "用户名或密码错误！");
            model.addAttribute("userName1", userName);
        } else if(EntUser.USERFROM_MEIMS.equals(entUser.getUserFrom())){
        	model.addAttribute("msg", "请登录太原市孵化园集群登记管理窗口办理业务。");
        }
        return "forward:/index.action";
    }

    /*
  * 返回登录弹框
  * */
    @RequestMapping("/selfLoginWindow.action")
    public String  selfLoginWindow(HttpServletRequest request,
                                   HttpServletResponse response, ModelMap model) throws LoginException,IOException,ParseException {
        return "template/selfQuery/selfLogin.html";
    }

    /*
    * 自主查询弹框登录
    * */
    @RequestMapping("/checkSelfLogin.action")
    @ResponseBody
    public Map<String,String> checkSelfLogin(HttpServletRequest request,
                                             HttpServletResponse response) throws LoginException,IOException,ParseException {
    	boolean phoneLoginFlag=codeService.getSysParameterAsBoolean(SysConstants.PHONELOGINFLAG);
    	Map<String,String> model = new HashMap<String, String>();
        HttpSession session = request.getSession();
        String userName = request.getParameter("userName");
        String passWord = request.getParameter("passWord");
        if(userName==null || "".equals(userName)){
            model.put("data","用户名或密码错误！");
            return model;
        }
        BASE64Decoder decoder = new BASE64Decoder();
        userName = new String(decoder.decodeBuffer(userName),"utf-8");
        passWord = new String(decoder.decodeBuffer(passWord),"utf-8");
        SimpleDateFormat sfd = new SimpleDateFormat("yyyy-MM-dd");
        Calendar c = Calendar.getInstance();
        c.setTime(sfd.parse(sfd.format(new Date())));
        String time = c.getTimeInMillis()+"";
        passWord=passWord.replace(time, "");
        String remPwd = request.getParameter("remPwd");
        EntUser entUser = entUserService.findByUsername(userName,phoneLoginFlag);
        if (entUser != null && MD5Util.checkPasswordMD5(passWord, entUser.getPassword())) {
            EntUser oldEntUser = (EntUser)session.getAttribute("entUser");
            if(oldEntUser!=null&&oldEntUser.getId()!=null&&!oldEntUser.getId().equals(entUser.getId())){
                session.removeAttribute("entUser");
            }
            if (entUser.getThisTime()==null) {
                entUser.setLastTime(new Date());
            } else {
                entUser.setLastTime(entUser.getThisTime());
            }
            entUser.setThisTime(new Date());
            session.setAttribute("entUser", entUser);
            entUserService.update(entUser);
            if (remPwd != null && remPwd.equals("true")) {
                CookieUtil.saveCookie(userName, passWord, response);
            } else {
                CookieUtil.clearCookie(response);
            }
            session.setAttribute("ToTopmeims", "N");
            model.put("data","校验通过！");
        }else{
            model.put("msg", "用户名或密码错误！");
            model.put("userName", userName);
        }
        return model;
    }
    
    @RequestMapping("/yyzzLogin.action")
    public String yyzzLogin(HttpServletRequest request,
                            HttpServletResponse response, ModelMap model,String licenceEntity, String signValue, String signText) throws LoginException {
   	 	HttpSession session = request.getSession();
   	 	String error = "";
        String syscode = codeService.getSysParameter(SysConstants.AuthSyscode);//电子营业执照系统代码
        String serviceURL = codeService.getSysParameter(SysConstants.businessLicenceServices);//远程接口地址
        System.out.println("执照：" + licenceEntity);
        System.out.println("签名值：" + signValue);
        System.out.println("签名原文：" + signText);
        System.out.println("电子营业执照系统代码：" + syscode);
        System.out.println("远程接口地址：" + serviceURL);

        int result_ = 0;
        boolean isOutRegisterAndCancel = codeService.getSysParameterAsBoolean(SysConstants.isOutRegisterAndCancel);
        URL url = null;
        URL baseUrl = null;
        baseUrl = auth.AuthenticationRemotServiceService.class.getResource(".");
        try {
            url = new URL(baseUrl, serviceURL);
        } catch (MalformedURLException e) {
            e.printStackTrace();
        }
        AuthenticationRemotServiceService service = new AuthenticationRemotServiceService(url);
        AuthenticationRemotService auth = service.getAuthenticationRemotServicePort();

        result_ = auth.businessLicenceVerifySign(licenceEntity, signText, signValue, syscode);
        System.out.println("签名验证结果!" + result_);
        if (result_ != 0) {
            error = "签名验证失败!";
            model.put("error", error);
            model.put("url", "/");
            return "template/errInfo.html";
        }
        String regno = ASN1Util.genInfoBy17(licenceEntity);
        System.out.println("企业注册号：" + regno);

        EntUser entUser = null;
        LepAndMarInfoOfUser lepAndMarInfo =  lepAndMarInfoService.findLepAndMarInfoByRegNoAndUserType(regno, LepAndMarInfoOfUser.USERTYPE_2);
        if (lepAndMarInfo!=null && lepAndMarInfo.getUserId()!=null) {
        	entUser = entUserService.findEntUserById(lepAndMarInfo.getUserId());
        }
        if (entUser == null) {
        	 entUser = new EntUser();
	       	 entUser.setUsername(regno);
	       	 entUser.setUserType("6");//电子营业执照登陆
	       	 entUserService.save(entUser);
        }
        model.put("regNo", regno);
        NetMainBody  nmb = busiMainBodyInfoService.getNetMainBodyByRegNo(regno);
        if (nmb != null) {
        	
            if(nmb.getState().equals(NetMainBody.MAINBODY_STATE_DISUSE)||nmb.getState().equals(NetMainBody.MAINBODY_STATE_TRANSFEROUT)){
				throw new RuntimeException("该企业已经迁出！");
			}else if(nmb.getState().equals(NetMainBody.MAINBODY_STATE_OUT) && !isOutRegisterAndCancel){
				throw new RuntimeException("该企业已被吊销！");
			}else if(nmb.getState().equals(NetMainBody.MAINBODY_STATE_TRANSFERIN_ING)){
				throw new RuntimeException("该企业正在做迁入迁出业务！");
			}else if(nmb.getState().equals(NetMainBody.MAINBODY_STATE_TYPEALTER_ING)){
				throw new RuntimeException("该企业正在做企业改制业务！");
			}else if(nmb.getState().equals(NetMainBody.MAINBODY_STATE_TYPEALTER_AFTER)){
				throw new RuntimeException("该企业正在做企业改制业务或已经迁出！");
			}else if(nmb.getState().equals(NetMainBody.MAINBODY_STATE_NOEFFECT)){
				throw new RuntimeException("无效主体数据！");
			}
        } else {
            throw new RuntimeException("无法找到主体表数据！");
        }
        if (entUser.getThisTime()==null) {
        	entUser.setLastTime(new Date());
        } else {
        	entUser.setLastTime(entUser.getThisTime());
        }
        entUser.setThisTime(new Date());
        session.setAttribute("entUser", entUser);
        CookieUtil.clearCookie(response);
        return "redirect:/toUserCenter.action";//业务引导
   }
  
    @RequestMapping("/dzyyzzLogin.action")
    public String dzyyzzLogin(HttpServletRequest request,HttpServletResponse response, ModelMap model) throws LoginException{
    	HttpSession session = request.getSession();
    	String tokenNo = (String) request.getParameter("token");
//    	String tokenNo="bdb19df745ae445ebac060bfa32a845c";
    	boolean phoneLoginFlag=codeService.getSysParameterAsBoolean(SysConstants.PHONELOGINFLAG);
        boolean isOutRegisterAndCancel = codeService.getSysParameterAsBoolean(SysConstants.isOutRegisterAndCancel);
        String sysCode = codeService.getSysParameter(SysConstants.AuthSyscode);//电子营业执照系统代码
        String serviceURL = codeService.getSysParameter(SysConstants.businessLicenceServices);//远程接口地址
        System.out.println("电子营业执照系统代码：" + sysCode);
        System.out.println("远程接口地址：" + serviceURL);
        String error="";
        //调用远程接口返回企业xml数据
        String result_ = DzyyzzInterfaceUtil.tokenFun(serviceURL,tokenNo, sysCode);
       
        if(result_!=null){
        	String codeValue = DzyyzzInterfaceUtil.getCode(result_);
        	//String codeValue="2";
        	if(!codeValue.equals("0")){
//        		 error = "验证失败!";
//                 model.put("error", error);
        		throw new RuntimeException("调用公示版签发接口失败！！");
                // return "template/error/runerror.html";	
        	}else{
        		String uniScID =DzyyzzInterfaceUtil.getUniScID(result_); 
        		//String uniScID="91341000MA2N61UG98";
        		 NetMainBody  nmb = busiMainBodyInfoService.getNetMainBodyByRegNo(uniScID);
        		 EntUser entUser = entUserService.findByUsername(uniScID,phoneLoginFlag);
        		 if(nmb!=null){
                         if(nmb.getState().equals(NetMainBody.MAINBODY_STATE_DISUSE)||nmb.getState().equals(NetMainBody.MAINBODY_STATE_TRANSFEROUT)){
             				throw new RuntimeException("该企业已经迁出！");
             			}else if(nmb.getState().equals(NetMainBody.MAINBODY_STATE_OUT) && !isOutRegisterAndCancel){
             				throw new RuntimeException("该企业已被吊销！");
             			}else if(nmb.getState().equals(NetMainBody.MAINBODY_STATE_TRANSFERIN_ING)){
             				throw new RuntimeException("该企业正在做迁入迁出业务！");
             			}else if(nmb.getState().equals(NetMainBody.MAINBODY_STATE_TYPEALTER_ING)){
             				throw new RuntimeException("该企业正在做企业改制业务！");
             			}else if(nmb.getState().equals(NetMainBody.MAINBODY_STATE_TYPEALTER_AFTER)){
             				throw new RuntimeException("该企业正在做企业改制业务或已经迁出！");
             			}else if(nmb.getState().equals(NetMainBody.MAINBODY_STATE_NOEFFECT)){
             				throw new RuntimeException("无效主体数据！");
             			}
        			 if (entUser == null) {
                    	 entUser = new EntUser();
            	       	 entUser.setUsername(uniScID);
            	       	 entUser.setPassword(MD5Util.createEncryptPSW(uniScID));
            	       	
            	       	 //电话号码
            	       	 if(nmb.getPhone()!=null&&!nmb.getPhone().equals("")){
            	       		entUser.setTel(nmb.getPhone()); 
            	       	 }
            	       	 //邮箱
            	       	 if(nmb.getEmail()!=null&&!nmb.getEmail().equals("")){
            	       		 entUser.setEmail(nmb.getEmail());
            	       	 }
            	       //1.查询法定代表人信息(代理人设置为法定代表人)
     					NetLegalPerson netLegalPerson=busService.findNetLegalPersonByMarprid(nmb.getId());
     					if(netLegalPerson!=null){
     						entUser.setElename(netLegalPerson.getName());//代理人姓名
     						entUser.setElepaper(netLegalPerson.getCertificateType());//代理人证件类型
     						entUser.setElepapernumber(netLegalPerson.getCertificateCode());//代理人证件号码
     					}else{
     						//2.查询执行事务合伙人信息
     						List<ExecutivePartner> executivePartnerList=busService.findExecutivePartnersByMarprid(nmb.getId());
     						if(executivePartnerList.size()>0){
     							ExecutivePartner executivePartner =executivePartnerList.get(0);
         						entUser.setElename(executivePartner.getName());//代理人姓名
         						entUser.setElepaper(executivePartner.getCertificateType());//代理人证件类型
         						entUser.setElepapernumber(executivePartner.getCertificateCode());//代理人证件号码
         					}
     					}
            	       	 entUser.setUserType("8");//电子营业执照登陆
            	       	 entUserService.save(entUser);
                    }
        			 entUser = entUserService.findByUsername(uniScID,phoneLoginFlag);
                    	LepAndMarInfoOfUser lepMarUser = lepAndMarInfoService.findLepAndMarInfoByMarprIdAnduserId(nmb.getId(), entUser.getId());
                    	if(lepMarUser==null){
                    		lepMarUser = new LepAndMarInfoOfUser();
                    	}
                    	lepMarUser.setUserId(entUser.getId());
                    	 //统一社会信用代码(优先填入统一社会信用代码)
                    	if(nmb.getUniScID()!=null&&!nmb.getUniScID().equals("")){
                    		lepMarUser.setUniscId(nmb.getUniScID());
                    	}
                    	if(lepMarUser.getUniscId()!=null){
                    		 //注册号
                  	       	 if(nmb.getCertificateNo()!=null&&!nmb.getCertificateNo().equals("")){
                  	       	lepMarUser.setUniscId(nmb.getCertificateNo()); 
                  	       	 }
                    	}
                    	//1.查询法定代表人信息
    					NetLegalPerson netLegalPerson=busService.findNetLegalPersonByMarprid(nmb.getId());
    					if(netLegalPerson!=null){
    						lepMarUser.setName(netLegalPerson.getName());//法人姓名	
    						lepMarUser.setCerType(netLegalPerson.getCertificateType());//法人证件类型
    						lepMarUser.setCerNo(netLegalPerson.getCertificateCode());//法人证件号码
    					}else{
    						//2.查询执行事务合伙人信息
    						List<ExecutivePartner> executivePartnerList=busService.findExecutivePartnersByMarprid(nmb.getId());
    						if(executivePartnerList.size()>0){
    							ExecutivePartner executivePartner =executivePartnerList.get(0);
    							lepMarUser.setName(executivePartner.getName());//法人姓名	
    							lepMarUser.setCerType(executivePartner.getCertificateType());//法人证件类型
    							lepMarUser.setCerNo(executivePartner.getCertificateCode());//法人证件号码
        					}
    					}
                    	lepMarUser.setEntName(nmb.getName());
                    	lepMarUser.setMarprId(nmb.getId());
                    	lepMarUser.setCreateTime(new Date());
                    	lepMarUser.setModiDate(new Date());
                    	lepMarUser.setChoseSign("Y");
                    	lepMarUser.setUserType("2");
                    	UserCenterAction userCenterAction = new UserCenterAction();
                    	lepMarUser.setUserLevel(userCenterAction.getUserLevel(nmb,lepMarUser,entUser));
                    	
                    	if(lepMarUser.getId()!=null){
                    		//更新
                    		lepAndMarInfoService.updateLepAndMarInfoOfUser(lepMarUser);
                    	}else{
                    		//插入
                    		lepAndMarInfoService.saveLepAndMarInfoOfUser(lepMarUser);
                    	}
        		 } else {
                     throw new RuntimeException("无法找到主体表数据！");
                 }
                if (entUser.getThisTime()==null) {
                	entUser.setLastTime(new Date());
                } else {
                	entUser.setLastTime(entUser.getThisTime());
                }
                entUser.setThisTime(new Date());
                session.setAttribute("entUser", entUser);
                CookieUtil.clearCookie(response);
        	}
		}
        
    	return "redirect:/toUserCenter.action";//业务引导	
    }
    @RequestMapping("/registerTips.action")
    public String registerTips(HttpServletRequest request,
                           HttpServletResponse response, ModelMap model) {
        SysConfig config = adminService.getSysConfig(SysConfig.ZCXZ);
        if(config!=null){
            model.put("location",  config.getName());
            model.put("config", config);
        }else{
            throw new RuntimeException("请初始化用户信息后进行重试！");
        }
        return "/template/registerTips.html";
    }
    @RequestMapping("/register.action")
    public String register(HttpServletRequest request,
                           HttpServletResponse response, ModelMap model) {
        model.put("cerTypes", codeService.getAllCertificateTypeCode());
        model.put("isShowCerType",codeService.getSysParameterAsBoolean(SysConstants.isShowCerType));
        model.put("location", "用户注册");
        model.put("weChat", "1");//首页二维码图片
        String type = request.getParameter("type");
        if (type == null || type.equals("")) {
            type = "sj";
        } 
        model.put("type", type);
        boolean uniScIDSign = codeService.getSysParameterAsBoolean(SysConstants.uniScIDSign);
        model.put("uniScIDSign", uniScIDSign);
        boolean isPhoneCode = codeService.getSysParameterAsBoolean(SysConstants.isPhoneCode);
        model.addAttribute("isPhoneCode",isPhoneCode);
        String loginWay=codeService.getSysParameter(SysConstants.loginWay);
        model.addAttribute("loginWay",loginWay);
        model.put("yyzzRegister",codeService.getSysParameterAsBoolean(SysConstants.yyzzRegister));
   		model.put("phoneRegCerType",codeService.getSysParameterAsBoolean(SysConstants.phoneRegCerType));
        model.put("bLicTypes", codeService.getAllBLicTypeCode());
    	model.put("useAnHuiCA",codeService.getSysParameterAsBoolean(SysConstants.userAnHuiCA));
    	model.put("realNameSMRZ", codeService.getSysParameterAsBoolean(SysConstants.realNameSMRZ));
    	model.put("smrz_policWay", codeService.getSysParameter(SysConstants.smrz_policWay));
		return "/template/login/newAllRegister.html";
        
    }

    @RequestMapping("/checkName.action")
    @ResponseBody
    public String checkName(HttpServletRequest request,
                            HttpServletResponse response, ModelMap model) {
        String userName = request.getParameter("username");
        if (userName != null && !"".equals(userName.trim())) {
            String str = entUserService.findUserName(userName);
            if (str.equals(userName)) {
                return "str";
            } else {
                return "redirect:/index.action";
            }
        }
        return "/template/login/register.html";
    }
    @RequestMapping("/checkEntUser.action")
    @ResponseBody
    public String checkEntUser(HttpServletRequest request,
                            HttpServletResponse response, ModelMap model) {
        String userName = request.getParameter("username");
        String eleName = request.getParameter("eleName");
        String tel = request.getParameter("tel");
        String elepapernumber = request.getParameter("elepapernumber");
        String email = request.getParameter("email");
        if (userName == null) {
        	userName = "";
        } else {
        	userName = userName.trim().replaceAll(" ", "");
        }

        if (eleName == null) {
        	eleName = "";
        } else {
        	eleName = eleName.trim().replaceAll(" ", "");
        }
        if (tel == null) {
        	tel = "";
        } else {
        	tel = tel.trim().replaceAll(" ", "");
        }
        if (email == null) {
        	email = "";
        } else {
        	email = email.trim().replaceAll(" ", "");
        }
        if (elepapernumber == null) {
        	elepapernumber = "";
        } else {
        	elepapernumber = elepapernumber.trim().replaceAll(" ", "");
        }
        String str="";
        EntUser entuser=null;
        if (userName != null && !"".equals(userName.trim())) {
        	boolean phoneLoginFlag=codeService.getSysParameterAsBoolean(SysConstants.PHONELOGINFLAG);
            entuser=entUserService.findByUsername(userName.trim(),phoneLoginFlag);
            if (entuser!=null&&entuser.getUsername().equals(userName)) {
            	if(eleName!=null&&!eleName.equals(entuser.getElename())){
            		str+="1";
            	}
            	if(elepapernumber!=null&&!elepapernumber.toUpperCase().equals(entuser.getElepapernumber().toUpperCase().trim().replaceAll(" ", ""))){
            		str+="2";
            	}
            	if(tel!=null&&!tel.equals(entuser.getTel())){
            		str+="3";
            	}
            	if(email!=null&&!email.equals(entuser.getEmail())){
            		str+="4";
            	}
            	return str;
            } else {
                return "redirect:/index.action";
            }
        }
        return "/template/login/forgetPwd.action";
    }
    @RequestMapping("/checkRegNo.action")
    @ResponseBody
    public String checkRegNo(HttpServletRequest request,HttpServletResponse response, ModelMap model) throws UnsupportedEncodingException{
    	String regNo = request.getParameter("regNo");
    	if(regNo!=null){
    		try {
    			regNo = URLDecoder.decode(regNo, "utf-8");
    		} catch (Exception e1) {
    			System.out.println("注册号中文解码异常---");
    			e1.printStackTrace();
    		}
    	}
    	String leRep = request.getParameter("leRep");
    	leRep = URLDecoder.decode(leRep,"utf-8");
    	String legCerType = request.getParameter("legCerType");
    	String legCerNo = request.getParameter("legCerNo");
    	legCerNo = URLDecoder.decode(legCerNo,"utf-8");
    	if(regNo!=null && regNo!="" && leRep!=null && leRep!="" && legCerType!=null && legCerType!=""&& legCerNo!=null && legCerNo!=""){

            //region 十组杨志，20170317，DEV00203542，处理校验注册号和信用代码缺陷，上移netMainBody，添加findByRegNoOrUniScID，注释原获取entUser的代码
            NetMainBody netMainBody = busService.findNetMainBodyByRegNo(regNo);
//    		EntUser entUser = new EntUser();
//            if(null != netMainBody){
//            	
//                entUser = entUserService.findByRegNoOrUniScID((null == netMainBody.getCertificateNo()) ? "" : netMainBody.getCertificateNo()
//                                                                ,(null == netMainBody.getUniScID())? "" : netMainBody.getUniScID());
//            }
//    		if(entUser.getId()!=null){
//    			return "entUser";
//    		}

    		//根据配置项如果注册号查不到，则用统一社会信用代码查询
    		boolean uniScIDSign = codeService.getSysParameterAsBoolean(SysConstants.uniScIDSign);
    		model.put("uniScIDSign", uniScIDSign);
    		if(uniScIDSign){
	    		if(netMainBody==null){
	    			netMainBody = busService.findNetMainBodyByUniScID(regNo);
	    		}
    		}
    		if(netMainBody!=null){
    			//只有06状态的可以通过注册
    			if(netMainBody.getState().equals(NetMainBody.MAINBODY_STATE_NORMAL)){
    				//不管所有企业类型都先查法人表
    				NetLegalPerson netLegalPerson=busService.findNetLegalPersonByMarprid(netMainBody.getId());
	    			if(netLegalPerson!=null && leRep.equals(netLegalPerson.getName()) && legCerType.equals(netLegalPerson.getCertificateType()) && legCerNo.equals(netLegalPerson.getCertificateCode())){
	    				return "redirect:/index.action";
	    			}
    				//如果没有法人信息，则查执行事务合伙人表
    				if(netLegalPerson==null){
    					boolean sign = false;
    					List<ExecutivePartner> executivePartner=busService.findExecutivePartnersByMarprid(netMainBody.getId());
    					if(executivePartner!=null && executivePartner.size()>0){
    						for(ExecutivePartner e:executivePartner){
    							if(leRep.equals(e.getName()) && legCerType.equals(e.getCertificateType()) && legCerNo.equals(e.getCertificateCode())){
    								sign=true;
    								break;
    							}
    						}
    					}
    					if(sign){
							return "redirect:/index.action";
						}else{
							return "netLegalPerson";
						}
    				}
	    		return "netLegalPerson";
	    		//其他状态进行错误提示
    			}else if(netMainBody.getState().equals(NetMainBody.MAINBODY_STATE_CANCEL)){
    				return "07";
    			}else if(netMainBody.getState().equals(NetMainBody.MAINBODY_STATE_DISUSE)||netMainBody.getState().equals(NetMainBody.MAINBODY_STATE_TRANSFEROUT)){
    				return "0809";
    			}else if(netMainBody.getState().equals(NetMainBody.MAINBODY_STATE_OUT)){
    				return "11";
    			}else if(netMainBody.getState().equals(NetMainBody.MAINBODY_STATE_TRANSFERIN_ING)){
    				return "13";
    			}else if(netMainBody.getState().equals(NetMainBody.MAINBODY_STATE_TYPEALTER_ING)){
    				return "15";
    			}else if(netMainBody.getState().equals(NetMainBody.MAINBODY_STATE_TYPEALTER_AFTER)){
    				return "16";
    			}else if(netMainBody.getState().equals(NetMainBody.MAINBODY_STATE_NOEFFECT)){
    				return "20";
    			}
        	}else{
        		return "netMainBody";
        	}
    	}
    	return "/template/login/register.html";
    }
    @RequestMapping("/checkElePaperNumber.action")
    @ResponseBody
    public String checkElePaperNumber(HttpServletRequest request,
                                      HttpServletResponse response, ModelMap model) {
        String elePaperNumber = request.getParameter("elepapernumber");
        if (elePaperNumber != null && !"".equals(elePaperNumber.trim())) {
            List<BusiMainBodyInfo> list = busiMainBodyInfoService.findBusiMainBodyInfoByElePaperNumber(elePaperNumber);
            if (list != null && list.size() > 0) {
                for (int i = 0; i < list.size(); i++) {
                    if ("01".equals(list.get(i).getBusiType()) && !("09".equals(list.get(i).getState()))) {
                        return "str";
                    }
                }

            } else {
                return "redirect:/index.action";
            }
        }
        return "/template/login/register.html";
    }

    @RequestMapping("/save.action")
    public String save(HttpServletRequest request,
                       HttpServletResponse response, ModelMap model,String tel,String phoneCode) throws Exception {
        EntUser e = new EntUser();
        model.put("cerTypes", codeService.getAllCertificateTypeCode());
        model.put("isShowCerType",codeService.getSysParameterAsBoolean(SysConstants.isShowCerType));
        boolean isPhoneCode = codeService.getSysParameterAsBoolean(SysConstants.isPhoneCode);
        model.addAttribute("isPhoneCode", isPhoneCode);
        String username = request.getParameter("username");
        String elename = request.getParameter("elename");
        String elepapernumber = request.getParameter("elepapernumber");
        String telphone = request.getParameter("tel");
        String email = request.getParameter("email");
        model.put("username",username);
        model.put("elename",elename);
        model.put("elepapernumber",elepapernumber);
        model.put("tel",telphone);
        model.put("email",email);
        String pwd = MD5Util.createEncryptPSW(request.getParameter("password"));
        String validity = codeService.getSysParameter(SysConstants.VERICODEVALIDITYCONFIG);
        int effecTime = 5;
        if (validity != null && !"".equals(validity)) {
            effecTime=Integer.parseInt(validity);
        }
        String userCanUseModule = codeService.getSysParameter(SysConstants.userCanUseModule);
        boolean userflag = true;
        if (userCanUseModule.indexOf("03") == -1 && userCanUseModule.indexOf("04") == -1 && userCanUseModule.indexOf("05") == -1)
        {
            userflag = false;
        }
        String error = null;
        if (isPhoneCode) {
            List<DynamicPD> dynPDList = mesgService.findDynamicPDByEnUserTelAndNow(tel, new Date(), effecTime);
            if (dynPDList == null || dynPDList.size() <= 0) {
                DynamicPD dPD = mesgService.findDynamicPDByEnUserTelAndPD(tel, phoneCode);

                if (dPD != null && dPD.getId() != null) {
                    error = "手机验证码已失效！";
                } else {
                    error = "手机验证码错误！";
                }
                model.put("userflag", userflag);
                model.put("error", error);
                model.addAttribute("loginWay", codeService.getSysParameter(SysConstants.loginWay));
                return "/template/login/register.html";
            } else {
                DynamicPD dynamicPD = dynPDList.iterator().next();
                if (!dynamicPD.getDynamicPD().equals(phoneCode)) {
                    LoginLog loginLog = new LoginLog();
                    loginLog.setEnUserID(Long.parseLong(tel));
                    loginLog.setCreateDate(new Date());
                    loginLog.setState(LoginLog.LOGINFAILED);
                    mesgService.saveLoginLog(loginLog);
                    error = "手机验证码错误！";
                    model.put("error", error);
                    model.addAttribute("loginWay", codeService.getSysParameter(SysConstants.loginWay));
                    return "/template/login/register.html";
                }
            }
        }
        e.setUsername(request.getParameter("username"));
            e.setPassword(pwd);
            e.setUserType("2");
            e.setElename(request.getParameter("elename"));
            e.setElepaper(request.getParameter("elepaper"));
            e.setElepapernumber(request.getParameter("elepapernumber"));
            e.setEmail(request.getParameter("email"));
            e.setTel(request.getParameter("tel"));
            e.setUserFrom(EntUser.USERFROM_ICPSP);
            entUserService.save(e);
            model.put("register", "注册成功！");
            model.put("userflag",userflag);
            return "/template/login/register.html";
        }
    
    @RequestMapping("/registerSave.action")
    public String registerSave(HttpServletRequest request, HttpServletResponse response,ModelMap model,
    		String issuerDN,String signMsg,String cerSerialNo){
        model.put("cerTypes", codeService.getAllCertificateTypeCode());
        model.put("phoneRegCerType",codeService.getSysParameterAsBoolean(SysConstants.phoneRegCerType));
        boolean isPhoneCode = codeService.getSysParameterAsBoolean(SysConstants.isPhoneCode);
        model.put("isPhoneCode",isPhoneCode);
        model.put("location", "用户注册");
        boolean uniScIDSign = codeService.getSysParameterAsBoolean(SysConstants.uniScIDSign);
        model.put("uniScIDSign", uniScIDSign);
        model.put("useAnHuiCA",codeService.getSysParameterAsBoolean(SysConstants.userAnHuiCA));
        model.put("realNameSMRZ", codeService.getSysParameterAsBoolean(SysConstants.realNameSMRZ));
        model.put("bLicTypes", codeService.getAllBLicTypeCode());
    	String username = request.getParameter("username");
    	String password = request.getParameter("password");
    	String elename = request.getParameter("elename");
    	String elepaper = request.getParameter("elepaper");
    	String elepapernumber = request.getParameter("elepapernumber");
    	String tel = request.getParameter("tel");
    	String email = request.getParameter("email");
    	String userType = request.getParameter("userType");
    	String cerDN = request.getParameter("cerDN");
//    	String phoneCode = request.getParameter("phoneCode");
    	String entName = request.getParameter("entname");
    	EntUser entUser = new EntUser();
    	entUser.setUsername(username);
    	entUser.setPassword(password);//暂时先不进行加密，保存时再加密
    	entUser.setElename(elename);
    	entUser.setElepaper(elepaper);
    	entUser.setElepapernumber(elepapernumber);
    	entUser.setTel(tel);
    	entUser.setEmail(email);
    	entUser.setUserType(userType);
    	String phoneCheckError=null;
    	if(userType!=null){
    		entUser.setCerDN(cerDN);
    		if(userType.equals("3")){
	    		String cerNoOrRegNo = null;
	    		String eleNameOrEntName = null;
	    		eleNameOrEntName = elename;
	    		cerNoOrRegNo = elepapernumber;
	    		phoneCheckError = this.CARegisterSave(eleNameOrEntName,cerNoOrRegNo,elepaper,model,issuerDN, signMsg, cerSerialNo);
	    		if("false".equals(phoneCheckError)){
	    			phoneCheckError="注册失败，用户信息与数字证书不匹配！";
	    		}else if("error".equals(phoneCheckError)){
	    			phoneCheckError="注册失败，请稍候进行注册！";
	    		}
    		}
    	}
    	
    	if(phoneCheckError==null||"".equals(phoneCheckError)){
	    	entUser.setPassword(MD5Util.createEncryptPSW(entUser.getPassword()));//保存用户前进行密码加密
	        model.put("register", "注册成功！");
	        entUserService.save(entUser);
    	}else{
    		model.put("entname",entName);
    		model.put("register",phoneCheckError);
    		model.put("entUser1", entUser);
    	}
    	return "/template/login/newAllRegister.html";
    }
    
    //忘记密码
        @RequestMapping("/forgetPd.action")
    public String forgetPd(HttpServletRequest request,
                       HttpServletResponse response,  ModelMap model,String tel, String phoneCode){
        boolean isSendSms = codeService.getSysParameterAsBoolean(SysConstants.isSendSms);
        boolean isShowCerType = codeService.getSysParameterAsBoolean(SysConstants.isShowCerType);
        boolean phoneLoginFlag=codeService.getSysParameterAsBoolean(SysConstants.PHONELOGINFLAG);
        if(!isSendSms){
            model.put("cerTypes", codeService.getAllCertificateTypeCode());
            model.put("isShowCerType",isShowCerType);
        }
        model.put("location", "忘记密码");
        model.put("isSendSms", isSendSms);
        String elepapernumber = request.getParameter("elepapernumber");
        String userName = request.getParameter("username");
        String pwd = request.getParameter("password");
        String telphone = request.getParameter("tel");
        EntUser e = new EntUser();
        e.setUsername(request.getParameter("username"));
        e.setPassword(pwd);
        e.setTel(request.getParameter("tel"));
        pwd = MD5Util.createEncryptPSW(request.getParameter("password"));
        EntUser entuser = entUserService.findByUsername(userName,phoneLoginFlag);
        if(!"".equals(userName) &&  entuser!=null){
               String telphone1 = entuser.getTel();
              if ("".equals(telphone) || !telphone.equals(telphone1)) {
                model.put("tel", "手机号码与注册时输入的不一致");
                model.put("userName", userName);
                model.put("telphone", tel);
                if(!isSendSms){
                	 model.put("elepapernumber", elepapernumber);
                }
                return "/template/login/forgetPwd.html";
            }
            if(!isSendSms){
            	if(isShowCerType){
            		String elepaper = request.getParameter("elepaper");
            		if(elepaper==null||"".equals(elepaper)||!elepaper.equals(entuser.getElepaper())){
	            		model.put("cerNoMsg", "证件类型与注册时选择的不一致");
    	                model.put("userName", userName);
    	                model.put("telphone", tel);
    	                model.put("elepapernumber", elepapernumber);
    	                return "/template/login/forgetPwd.html";
            		}
            	}
            	if((elepapernumber==null||"".equals(elepapernumber)||!elepapernumber.equals(entuser.getElepapernumber()))){
	            	if(isShowCerType){
	            		model.put("cerNoMsg", "证件号码与注册时输入的不一致");
	            	}else{
	            		model.put("cerNoMsg", "身份证号码与注册时输入的不一致");
	            	}
	                model.put("userName", userName);
	                model.put("telphone", tel);
	                model.put("elepapernumber", elepapernumber);
	                return "/template/login/forgetPwd.html";
            	}
            }
        } else {
            model.put("fail", "用户名与注册时输入的不一致");
            model.put("userName", userName);
            model.put("telphone", tel);
            if(!isSendSms){
           	 model.put("elepapernumber", elepapernumber);
           }
           return "/template/login/forgetPwd.html";
        }
        if(isSendSms){
        	boolean testSign = false;//false不是演示环境
        	//允许在演示或者测试环境下不验证验证码
            String portStr = request.getServerPort()+"";
            String notlogin = codeService.getSysParameter("notlogin");
            if((!Strings.isNullOrEmpty(notlogin))&&(notlogin.equals("Y") && (portStr.equals("9080") || portStr.equals("9081") || portStr.equals("9082") || portStr.equals("9083") || portStr.equals("9088")))
             		|| (!"".equals(portStr)&&notlogin.contains(portStr))){
            	testSign = true;
             }
            if(!testSign){
		    	String validity = codeService.getSysParameter(SysConstants.VERICODEVALIDITYCONFIG);
		        int effecTime = 5;
		        if (validity != null && !"".equals(validity)) {
		            effecTime = Integer.parseInt(validity);
		        }
		        String error = null;
		        List<DynamicPD> dynPDList = mesgService.findDynamicPDByEnUserTelAndNow(tel, new Date(), effecTime);
		        if (dynPDList == null || dynPDList.size() <= 0) {
		            DynamicPD dPD = mesgService.findDynamicPDByEnUserTelAndPD(tel, phoneCode);
	
		            if (dPD != null && dPD.getId() != null) {
		                error = "手机验证码已失效！";
		            } else {
		                error = "手机验证码错误！";
		            }
		            model.put("register", error);
		            model.put("userName", userName);
		            model.put("telphone", tel);
		            model.put("entUser1", e);
			    	model.put("location", "忘记密码");
			 		model.addAttribute("loginWay",codeService.getSysParameter(SysConstants.loginWay));
			 		return "/template/login/forgetPwd.html";
		         } else {
		            DynamicPD dynamicPD = dynPDList.iterator().next();
		            if (!dynamicPD.getDynamicPD().equals(phoneCode)) {
		                LoginLog loginLog = new LoginLog();
		                loginLog.setEnUserID(Long.parseLong(tel));
		                loginLog.setCreateDate(new Date());
		                loginLog.setState(LoginLog.LOGINFAILED);
		                mesgService.saveLoginLog(loginLog);
		                error = "手机验证码错误！";
		                model.put("register", error);
		                model.put("userName", userName);
		                model.put("telphone", tel);
		                model.put("entUser1", e);
		                model.addAttribute("loginWay", codeService.getSysParameter(SysConstants.loginWay));
		                return "/template/login/forgetPwd.html";
		            }
		        }
            }
        }
    	EntUser entUser = entUserService.findByUsername(userName,phoneLoginFlag);
    	if(entUser!=null){
            entUser.setPassword(pwd);
    		entUserService.update(entUser);
    		model.put("forgetPd", "密码重置成功！");
    		model.put("location", "忘记密码");
    		model.addAttribute("loginWay",codeService.getSysParameter(SysConstants.loginWay));
    		return "/template/login/forgetPwd.html";
    	}else{
    		model.put("forgetPd", "密码重置失败！");
    		model.put("entUser1", e);
    		model.put("location", "忘记密码");
    		model.addAttribute("loginWay",codeService.getSysParameter(SysConstants.loginWay));
    	    return "/template/login/forgetPwd.html";
    	}
    }
    @RequestMapping("/sendPhoVerCode.action")
    @ResponseBody
    public Map<String, String> sendPhoVerCode(HttpServletRequest request, HttpServletResponse response, ModelMap model)
            throws Exception {
        Map map = new HashMap<String, String>();
        boolean phoneLoginFlag=codeService.getSysParameterAsBoolean(SysConstants.PHONELOGINFLAG);
        String username = request.getParameter("username");
        String tel = request.getParameter("tel");
        if (username != null && !username.isEmpty() && entUserService.findByUsername(username,phoneLoginFlag) != null) {
            tel = entUserService.findByUsername(username,phoneLoginFlag).getTel();
        }
        if (tel == null) {
            tel = "";
        } else {
            tel = java.net.URLDecoder.decode(tel, "UTF-8");
            tel = tel.trim();
        }
        String mark = request.getParameter("mark");
        if(mark!=null&&"phoneCheck".equals(mark)){
        	String msg = this.phoneCheck(tel, null);
        	if(msg!=null&&!"".equals(msg)){
        		map.put("error",msg);
        		return map;
        	}
        }

        int captchaCode = (int) ((Math.random() * 9 + 1) * 100000);
        String validity = codeService.getSysParameter(SysConstants.VERICODEVALIDITYCONFIG);
        int effecTime = 5;
        if (validity != null && !"".equals(validity)) {
            effecTime = Integer.parseInt(validity);
        }
        List<DynamicPD> dynPDList = mesgService.findDynamicPDByEnUserTelAndNow(tel, new Date(), effecTime);
        if (dynPDList != null && dynPDList.size() > 0) {
            DynamicPD dynamicPDOld = dynPDList.iterator().next();
            if (dynamicPDOld.getDynamicPD() != null && !"".equals(dynamicPDOld.getDynamicPD())) {
                captchaCode = Integer.parseInt(dynamicPDOld.getDynamicPD());
            }
        }
        try {

            DynamicPD dynamicPD = new DynamicPD();
            dynamicPD.setEnUserTel(tel);
            dynamicPD.setCreateDate(new Date());
            dynamicPD.setDynamicPD(String.valueOf(captchaCode));
            mesgService.saveDynamicPD(dynamicPD);
            SendMessageUtil.sendMsg(tel, String.valueOf(captchaCode));
            map.put("data", "短信发送成功！");
        } catch (Exception e) {
            e.printStackTrace();
            map.put("data", "短信发送失败！");
//                return "短信发送失败！";
        }
//            return "短信发送成功！";
        return map;
    }

    @SuppressWarnings("unchecked")
	@RequestMapping("/loginPhoVerCode.action")
    @ResponseBody
    public Map<String, String> loginPhoVerCode(HttpServletRequest request, HttpServletResponse response, ModelMap model)
            throws Exception {
        Map map = new HashMap<String, String>();
        String username = request.getParameter("username");
        String tel = request.getParameter("tel");
        String password = request.getParameter("password");
        String phoneCode = request.getParameter("phoneCode");
        boolean phoneLoginFlag=codeService.getSysParameterAsBoolean(SysConstants.PHONELOGINFLAG);
        EntUser entuser=entUserService.findByUsername(username,phoneLoginFlag);
        if (username != null && !username.isEmpty() && entuser!= null && MD5Util.checkPasswordMD5(password, entuser.getPassword())) {
            tel = entUserService.findByUsername(username,phoneLoginFlag).getTel();
        }else{
        	 map.put("data", "用户名或密码错误！");
        	 return map;
        }
        if (tel == null) {
            tel = "";
        } else {
            tel = java.net.URLDecoder.decode(tel, "UTF-8");
            tel = tel.trim();
        }

        int captchaCode = (int) ((Math.random() * 9 + 1) * 100000);
        String validity = codeService.getSysParameter(SysConstants.VERICODEVALIDITYCONFIG);
        int effecTime = 5;
        if (validity != null && !"".equals(validity)) {
            effecTime = Integer.parseInt(validity);
        }
        List<DynamicPD> dynPDList = mesgService.findDynamicPDByEnUserTelAndNow(tel, new Date(), effecTime);
        //验证码存在 登录操作
        if(phoneCode!=null){
        	if (dynPDList == null || dynPDList.size() <= 0) {
                LoginLog loginLog = new LoginLog();
                loginLog.setEnUserID(Long.parseLong(entuser.getTel()));
                loginLog.setCreateDate(new Date());
                loginLog.setState(LoginLog.LOGINFAILED);
                mesgService.saveLoginLog(loginLog);
                DynamicPD dPD = mesgService.findDynamicPDByEnUserTelAndPD(entuser.getTel(), phoneCode);
                if (dPD != null && dPD.getId() != null) {
                	map.put("data", "手机验证码已失效！");
                } else {
                	map.put("data", "手机验证码错误！");
                }
            } else {
        	DynamicPD dynamicPD = dynPDList.iterator().next();
            if (dynamicPD.getDynamicPD().equals(phoneCode)) {
            	map.put("data", "验证码正确！");
            }else{
            	map.put("data", "手机验证码错误！");
            }
            }
        	 return map;	
    	}else{ //验证码不存在  获取验证码操作
    		if (dynPDList != null && dynPDList.size() > 0) {
                DynamicPD dynamicPDOld = dynPDList.iterator().next();
                if (dynamicPDOld.getDynamicPD() != null && !"".equals(dynamicPDOld.getDynamicPD())) {
                    captchaCode = Integer.parseInt(dynamicPDOld.getDynamicPD());
                }
            }
            try {

                DynamicPD dynamicPD = new DynamicPD();
                dynamicPD.setEnUserTel(tel);
                dynamicPD.setCreateDate(new Date());
                dynamicPD.setDynamicPD(String.valueOf(captchaCode));
                mesgService.saveDynamicPD(dynamicPD);
                SendMessageUtil.sendMsg(tel, String.valueOf(captchaCode));
                map.put("data", "短信发送成功！");
            } catch (Exception e) {
                e.printStackTrace();
                map.put("data", "短信发送失败！");
            }
    	}
        return map;
    }
    
    @SuppressWarnings("unchecked")
	@RequestMapping("/validPhoVerCode.action")
    @ResponseBody
    public Map<String, String> validPhoVerCode(HttpServletRequest request, ModelMap model)
            throws Exception {
        Map map = new HashMap<String, String>();
        String phoneCode = request.getParameter("phoneCode");
        String tel = request.getParameter("tel");
        String validity = codeService.getSysParameter(SysConstants.VERICODEVALIDITYCONFIG);
        int effecTime = 5;
        if (validity != null && !"".equals(validity)) {
            effecTime = Integer.parseInt(validity);
        }
        List<DynamicPD> dynPDList = mesgService.findDynamicPDByEnUserTelAndNow(tel, new Date(), effecTime);
        //验证码存在 登录操作
        if(phoneCode!=null){
        	if (dynPDList == null || dynPDList.size() <= 0) {
                LoginLog loginLog = new LoginLog();
                loginLog.setEnUserID(Long.parseLong(tel));
                loginLog.setCreateDate(new Date());
                loginLog.setState(LoginLog.LOGINFAILED);
                mesgService.saveLoginLog(loginLog);
                DynamicPD dPD = mesgService.findDynamicPDByEnUserTelAndPD(tel, phoneCode);
                if (dPD != null && dPD.getId() != null) {
                	map.put("data", "手机验证码已失效！");
                } else {
                	map.put("data", "手机验证码错误！");
                }
            } else {
        	DynamicPD dynamicPD = dynPDList.iterator().next();
            if (dynamicPD.getDynamicPD().equals(phoneCode)) {
            	map.put("data", "验证码正确！");
            }else{
            	map.put("data", "手机验证码错误！");
            }
            }
    	}else{
    		map.put("data", "验证码不能为空！");
    	}
        return map;	
    }
    

    @RequestMapping("/verifyGetPhoVerCode.action")
    @ResponseBody
    public String verifyGetPhoVerCode(HttpServletRequest request, HttpServletResponse response, ModelMap model)
            throws Exception {
        String tel = request.getParameter("tel");
        if (tel == null) {
            tel = "";
        } else {
            tel = java.net.URLDecoder.decode(tel, "UTF-8");
            tel = tel.trim();
        }
        //允许在演示或者测试环境下不验证验证码
        String portStr = request.getServerPort()+"";
        String notlogin = codeService.getSysParameter("notlogin");
        if((!Strings.isNullOrEmpty(notlogin))&&(notlogin.equals("Y") && (portStr.equals("9080") || portStr.equals("9081") || portStr.equals("9082") || portStr.equals("9083") || portStr.equals("9088")))
         		|| (!"".equals(portStr)&&notlogin.contains(portStr))){
        	return "true";
         }

        int dynPDNum = mesgService.findDynamicPDCountByEnUserTelAndToday(tel, new Date());
        if (dynPDNum == 0) {
            return "请先获取备案手机验证码！";
        } else {
            return "true";
        }
    }
    @RequestMapping("/deal.action")
        public String deal(HttpServletRequest request, HttpServletResponse response){
            return "/template/login/deal.html";
    }

    @RequestMapping("/phonesave.action")
    public String login(HttpServletRequest request, HttpServletResponse response, ModelMap model,
                        String tel, String phoneCode)
            throws Exception {
        if (tel == null) {
            tel = "";
        } else {
            tel = tel.trim();
        }
        if (phoneCode == null) {
            phoneCode = "";
        } else {
            phoneCode = phoneCode.trim();
        }
        EntUser e = new EntUser();
        model.put("cerTypes", codeService.getAllCertificateTypeCode());
        String pwd = request.getParameter("password");
        e.setUsername(request.getParameter("username"));
        e.setPassword(pwd);
        e.setUserType("2");
        e.setElename(request.getParameter("elename"));
        e.setElepaper(request.getParameter("elepaper"));
        e.setElepapernumber(request.getParameter("elepapernumber"));
        e.setEmail(request.getParameter("email"));
        e.setTel(request.getParameter("tel"));
        String error = "";
        model.put("type", "sj");
        model.put("loginWay", codeService.getSysParameter(SysConstants.loginWay));
        String portStr = (Integer.toString(request.getServerPort()));
        String notlogin = codeService.getSysParameter("notlogin");
        if((!Strings.isNullOrEmpty(notlogin))&&(notlogin.equals("Y") && (portStr.equals("9080") || portStr.equals("9081") || portStr.equals("9082") || portStr.equals("9083") || portStr.equals("9088")))
         		|| (!"".equals(portStr)&&notlogin.contains(portStr))){
        	//保存用户信息
            pwd = MD5Util.createEncryptPSW(request.getParameter("password"));
            e.setPassword(pwd);
            model.put("register", "注册成功！");
            e.setUserFrom(EntUser.USERFROM_ICPSP);
            entUserService.save(e);
            return "/template/login/allregister.html";
         }
        String validity = codeService.getSysParameter(SysConstants.VERICODEVALIDITYCONFIG);
        int effecTime = 5;
        if (validity != null && !"".equals(validity)) {
            effecTime = Integer.parseInt(validity);
        }
        List<DynamicPD> dynPDList = mesgService.findDynamicPDByEnUserTelAndNow(tel, new Date(), effecTime);
        if (dynPDList == null || dynPDList.size() <= 0) {
            LoginLog loginLog = new LoginLog();
            loginLog.setEnUserID(Long.parseLong(tel));
            loginLog.setCreateDate(new Date());
            loginLog.setState(LoginLog.LOGINFAILED);
            mesgService.saveLoginLog(loginLog);
            DynamicPD dPD = mesgService.findDynamicPDByEnUserTelAndPD(tel, phoneCode);
            if (dPD != null && dPD.getId() != null) {
                error = "手机验证码已失效！";
            } else {
                error = "手机验证码错误！";
            }
            model.put("register", error);
            model.put("entUser1", e);
            return "/template/login/allregister.html";
        } else {
            DynamicPD dynamicPD = dynPDList.iterator().next();
            if (!dynamicPD.getDynamicPD().equals(phoneCode)) {
                LoginLog loginLog = new LoginLog();
                loginLog.setEnUserID(Long.parseLong(tel));
                loginLog.setCreateDate(new Date());
                loginLog.setState(LoginLog.LOGINFAILED);
                mesgService.saveLoginLog(loginLog);
                error = "手机验证码错误！";
                model.put("register", error);
                model.put("entUser1", e);
                return "/template/login/allregister.html";
            } else {
                LoginLog loginLog = new LoginLog();
                loginLog.setEnUserID(Long.parseLong(tel));
                loginLog.setCreateDate(new Date());
                loginLog.setState(LoginLog.LOGINSUCCEED);
                mesgService.saveLoginLog(loginLog);
            }
        }
        pwd = MD5Util.createEncryptPSW(request.getParameter("password"));
        e.setPassword(pwd);
        e.setUserFrom(EntUser.USERFROM_ICPSP);
        entUserService.save(e);
        model.put("register", "注册成功！");
        return "/template/login/allregister.html";
    }

    @RequestMapping("/phonelogin.action")
    public String phonelogin(HttpServletRequest request,
                             HttpServletResponse response, ModelMap model) throws LoginException, UnsupportedEncodingException, IOException, ParseException {
        String info = "";
        HttpSession session = request.getSession();
        String userName = request.getParameter("username2");
        String passWord = request.getParameter("password2");
        if(userName==null || "".equals(userName)){
        	return "forward:/index.action";
        }
        boolean phoneLoginFlag=codeService.getSysParameterAsBoolean(SysConstants.PHONELOGINFLAG);
        BASE64Decoder decoder = new BASE64Decoder();
        userName = new String(decoder.decodeBuffer(userName),"utf-8");
        passWord = new String(decoder.decodeBuffer(passWord),"utf-8");
        Calendar c = Calendar.getInstance();
        c.setTime(new Date());
        c.set(Calendar.HOUR_OF_DAY, 0);
        c.set(Calendar.MINUTE, 0);
        c.set(Calendar.SECOND, 0);
        c.set(Calendar.MILLISECOND, 0);
        String time = c.getTimeInMillis() + "";
        passWord=passWord.replace(time, "");
        EntUser entUser = entUserService.findByUsername(userName,phoneLoginFlag);
        String phoneCode = request.getParameter("phoneCode");
//        boolean isOutRegisterAndCancel = codeService.getSysParameterAsBoolean(SysConstants.isOutRegisterAndCancel);

        if (entUser != null && MD5Util.checkPasswordMD5(passWord, entUser.getPassword())) {
            String validity = codeService.getSysParameter(SysConstants.VERICODEVALIDITYCONFIG);
            int effecTime = 5;
            if (validity != null && !"".equals(validity)) {
                effecTime = Integer.parseInt(validity);
            }
            List<DynamicPD> dynPDList = mesgService.findDynamicPDByEnUserTelAndNow(entUser.getTel(), new Date(), effecTime);
            String notlogin = codeService.getSysParameter("notlogin");
            String portStr = request.getServerPort()+"";
            if((!Strings.isNullOrEmpty(notlogin))&&(notlogin.equals("Y") && (portStr.equals("9080") || portStr.equals("9081") || portStr.equals("9082") || portStr.equals("9083") || portStr.equals("9088")))
             		|| (!"".equals(portStr)&&notlogin.contains(portStr))){
             }else{
            	 if (dynPDList == null || dynPDList.size() <= 0) {
                     LoginLog loginLog = new LoginLog();
                     loginLog.setEnUserID(Long.parseLong(entUser.getTel()));
                     loginLog.setCreateDate(new Date());
                     loginLog.setState(LoginLog.LOGINFAILED);
                     mesgService.saveLoginLog(loginLog);
                     DynamicPD dPD = mesgService.findDynamicPDByEnUserTelAndPD(entUser.getTel(), phoneCode);
                     if (dPD != null && dPD.getId() != null) {
                         info = "手机验证码已失效！";
                     } else {
                         info = "手机验证码错误！";
                     }
                 } else {
                     DynamicPD dynamicPD = dynPDList.iterator().next();
                     if (!dynamicPD.getDynamicPD().equals(phoneCode)) {
                         LoginLog loginLog = new LoginLog();
                         loginLog.setEnUserID(Long.parseLong(entUser.getTel()));
                         loginLog.setCreateDate(new Date());
                         loginLog.setState(LoginLog.LOGINFAILED);
                         mesgService.saveLoginLog(loginLog);
                         info = "手机验证码错误！";
                         model.addAttribute("msg", info);
                         model.addAttribute("passWord1", passWord);
                         model.addAttribute("userName1", userName);
                         return "forward:/index.action";
                     } else {
                         LoginLog loginLog = new LoginLog();
                         loginLog.setEnUserID(Long.parseLong(entUser.getTel()));
                         loginLog.setCreateDate(new Date());
                         loginLog.setState(LoginLog.LOGINSUCCEED);
                         mesgService.saveLoginLog(loginLog);
                     }
                 }
            }
           
            if (!info.isEmpty()) {
                model.addAttribute("msg", info);
                model.addAttribute("userName1", userName);
                model.addAttribute("passWord1", passWord);
                return "forward:/index.action";
            }
            EntUser oldEntUser = (EntUser)session.getAttribute("entUser");
            if(oldEntUser!=null&&oldEntUser.getId()!=null&&!oldEntUser.getId().equals(entUser.getId())){
            	session.removeAttribute("entUser");
            }
            if (entUser.getThisTime()==null) {
            	entUser.setLastTime(new Date());
            } else {
            	entUser.setLastTime(entUser.getThisTime());
            }
            entUser.setThisTime(new Date());
            session.setAttribute("entUser", entUser);
            entUserService.update(entUser);
            boolean userHandleEntForManyFlag = codeService.getSysParameterAsBoolean(SysConstants.UserHandleEntForManyFlag);
        	String ToTopmeims="";
            if(request.getSession().getAttribute("ToTopmeims")!=null){
            	ToTopmeims = (String) request.getSession().getAttribute("ToTopmeims");//孵化员标识
            }
            if("Y".equals(ToTopmeims)){
            	userHandleEntForManyFlag=true;
            }
          //删除实名认证提示标识
            request.getSession().removeAttribute("realNameTipFlag");
            if (userHandleEntForManyFlag) {
            	if(codeService.getSysParameterAsBoolean(SysConstants.USERCENTER)){
            		return "redirect:/toUserCenter.action";//用户中心
            	}
        		int count = busiMainBodyInfoService.findBusiMainBodyInfoCountByUserIdAndBusiType(
                        entUser.getId(), new String[]{BusiMainBodyInfo.BUSITYPE_MC,BusiMainBodyInfo.BUSITYPE_SL});
                if (count>0) {//进入列表页面
                    return "redirect:/nameAndRegisterList.action";
                }
                return "redirect:/toUserCenter.action";//业务引导
            }else{
            	
            	BusiMainBodyInfo info1 = busiMainBodyInfoService.findBusiMainBodyInfoByUserIdAndBusiType(
                        entUser.getId(), BusiMainBodyInfo.BUSITYPE_MC);
                BusiMainBodyInfo info2 = busiMainBodyInfoService.findBusiMainBodyInfoByUserIdAndBusiType(
                        entUser.getId(), BusiMainBodyInfo.BUSITYPE_SL);
                if (info2 != null && info2.getId() != null) {//进入设立流程图
                    return "redirect:/flowChoices.action?busType=02&busiId="+info2.getId();
                } else if (info1 != null && info1.getId() != null) {//进入名称流程图
                    return "redirect:/flowChoices.action?busType=01&busiId="+info1.getId();
                }
            	return "redirect:/toUserCenter.action";//业务引导
            }
        } else if (entUser == null) {
            model.addAttribute("msg", "用户不存在！");
        } else if (!MD5Util.checkPasswordMD5(passWord, entUser.getPassword())) {
            model.addAttribute("msg", "密码错误！");
            model.addAttribute("userName1", userName);
        }
        return "forward:/index.action";
    }


    @RequestMapping("/cfcaRegSave.action")
    public String cfcaRegSave(HttpServletRequest request, HttpServletResponse response,
                              ModelMap model, String cerDN, String cerSerialNo,
                              String issuerDN,String signMsg)
            throws Exception {

        EntUser e = new EntUser();
        String userName = request.getParameter("elename");
        String cerType = request.getParameter("elepaper");
        String cerNo = request.getParameter("elepapernumber");
        model.put("cerTypes", codeService.getAllCertificateTypeCode());
        model.put("loginWay", codeService.getSysParameter(SysConstants.loginWay));
        model.put("type", "cfca");
        String pwd = MD5Util.createEncryptPSW(request.getParameter("password"));
        e.setUsername(request.getParameter("username"));
        e.setPassword(pwd);
        e.setUserType("3");
        e.setElename(userName);
        e.setElepaper(cerType);
        e.setElepapernumber(cerNo);
        e.setEmail(request.getParameter("email"));
        e.setTel(request.getParameter("tel"));
        e.setCerDN(cerDN);
        /*---------------------------CFCA认证开始--------------------------*/
        if (cerType != null && cerType.equals("10")) {
            cerType = "0";//系统中的身份证1对应认证系统中的身份证代码0
        } else if (cerType != null && cerType.equals("30")) {
            cerType = "A";//系统中的警官证3对应认证系统中的警官证A
        } else if (cerType != null && cerType.equals("40")) {
            cerType = "1";//系统中的护照4对应认证系统中的护照1
        } else if (cerType != null && cerType.equals("90")) {
            cerType = "Z";//系统中的护照4对应认证系统中的护照1
        }
        System.out.println("============issuerDN==========="+issuerDN);
        System.out.println("============signMsg==========="+signMsg);
        String cfcaUrl = codeService.getSysParameter("cfcaUrl");
        try {
            int connectTimeout = 3000;
            int readTimeout = 30000;
            UAClient client = new UAClient(cfcaUrl, connectTimeout, readTimeout);
            AuthenticateVO authenticateVO = new AuthenticateVO();
            if (cerDN != null && cerDN.contains("OU=BGB")) {
                Signature sigUtil = new Signature();
                JCrypto.getInstance().initialize(JCrypto.JSOFT_LIB, null);
                Session session = JCrypto.getInstance().openSession(JCrypto.JSOFT_LIB);
                if (sigUtil.p7VerifyMessageAttach(signMsg.getBytes("utf-8"), session)) {
                    authenticateVO.setTxCode("02001");
                    authenticateVO.setSubscriberName(userName);
                    authenticateVO.setIdentificationTypeCode(cerType);
                    //目前只有身份证类型，证件号码前加0
                    authenticateVO.setIdentificationNo("0"+cerNo);
                    authenticateVO.setSerialNo(cerSerialNo);
                    authenticateVO.setIssuerDn(issuerDN);
                    authenticateVO.setQueryCertStatus("true");
                    authenticateVO.setValidateIdentTypeCode("true");
                } else {
                    throw new RuntimeException("数字证书签名认证失败，请查证！");
                }
            } else {
                authenticateVO.setTxCode("10002");
                authenticateVO.setSubscriberName(userName);
                authenticateVO.setIdentificationTypeCode(cerType);
                //目前只有身份证类型，证件号码前加0
                authenticateVO.setIdentificationNo("0"+cerNo);
                authenticateVO.setSignature(signMsg);
            }
            SubscriberVO subscriberVO = (SubscriberVO) client.process(authenticateVO);
            System.out.println(subscriberVO.getResultCode());
            System.out.println(subscriberVO.getResultMessage());
            if(UAClient.SUCCESS.equals(subscriberVO.getResultCode())){
                if (subscriberVO.getStatus().equals("0")) {
                	e.setUserFrom(EntUser.USERFROM_ICPSP);
                    entUserService.save(e);
                    model.put("register", "注册成功！");
                } else {
                    model.put("register", "注册失败！");
                     if(subscriberVO.getStatus().equals("1")){
                         throw new RuntimeException("数字证书签名认证失败(原因：匹配成功，证书已过期)！");
                     }else  if(subscriberVO.getStatus().equals("2")){
                         throw new RuntimeException("数字证书签名认证失败(原因：匹配成功，证书已吊销)！");
                     } else  if(subscriberVO.getStatus().equals("3")){
                         throw new RuntimeException("数字证书签名认证失败(原因：用户信息不匹配)！");
                     }  else  if(subscriberVO.getStatus().equals("9")){
                         throw new RuntimeException("数字证书签名认证失败(原因：证书未知)！");
                     }else {
                         throw new RuntimeException("数字证书签名认证失败！");
                     }
                }
            }else{
                model.put("register", "注册失败！");
                throw new RuntimeException("注册失败，请重新获取数字证书后再次注册！");
            }


        } catch (ClientException ee) {
            model.put("register", "注册失败！");
            ee.printStackTrace();
        }

        return "/template/login/allregister.html";
    }

    @RequestMapping("/whLogin.action")
    public String whLogin(HttpServletRequest request, HttpServletResponse response, HttpSession session,
                      ModelMap model,String serviceTicket,String busiType) throws IOException{
    	if(serviceTicket==null || "".equals(serviceTicket)){
//    		serviceTicket="93404c09-8b0d-404a-84ae-b9c1378818b6";
    		throw new RuntimeException("serviceTicket为空！");
    	}
    	if(busiType==null || "".equals(busiType)){
    		throw new RuntimeException("busiType为空！");
    	}
    	String casUrl = codeService.getSysParameter(SysConstants.CAS_URL);
//    	casUrl="http://t.eqiwang.cn/cas/validateJson";
    	String param="?appId="+SysConstants.APP_ID+"&secret="+SysConstants.APP_SECRET+"&serviceTicket="+serviceTicket;
    	URL url=new URL(casUrl+param);
    	URLConnection conn = url.openConnection();
    	InputStream in = conn.getInputStream();
    	StringBuffer sb=new StringBuffer();

    	Scanner sc=new Scanner(in,"utf-8");
    	while(sc.hasNextLine()){
    		sb.append(sc.nextLine());
    	}
    	in.close();
    	System.out.println("返回值："+sb.toString());
    	System.out.println("----------------------------busiType:" + busiType + "------------------------");
    	System.out.println("URL:"+url.toString());
    	JSONObject obj=JSONObject.fromObject(sb.toString());
    	if(obj.getBoolean("success")){
//    		返回值：{"success":"true","userName":"zyz123"}
    		String userName=obj.getString("userName");
    		String registNumber=obj.getString("registNumber");
    		Boolean reCreate=false;
			EntUser user=null;
			if(registNumber!=null && !"".equals(registNumber)&&(
	    			BusiMainBodyInfo.BUSITYPE_BG.equals(busiType) ||BusiMainBodyInfo.BUSITYPE_ZX.equals(busiType)
	    			||BusiMainBodyInfo.BUSITYPE_BA.equals(busiType) ||BusiMainBodyInfo.BUSITYPE_QSZBA.equals(busiType) )){
				LepAndMarInfoOfUser lepAndMarInfo = lepAndMarInfoService.findLepAndMarInfoByRegNoAndUserType(registNumber, LepAndMarInfoOfUser.USERTYPE_3);
				if (lepAndMarInfo!=null && lepAndMarInfo.getUserId()!=null) {
					user = entUserService.findEntUserById(lepAndMarInfo.getUserId());
				}
	    	//不管有没有注册号只要业务类型是01、02的根据用户名查找只能做名称或者设立业务
	    	}else if(BusiMainBodyInfo.BUSITYPE_MC.equals(busiType) ||BusiMainBodyInfo.BUSITYPE_SL.equals(busiType)){
	    		boolean phoneLoginFlag=codeService.getSysParameterAsBoolean(SysConstants.PHONELOGINFLAG);
	    		user = entUserService.findByUsername(userName,phoneLoginFlag);
	    	}
    		if(user==null || user.getId()==null){
    			reCreate=true;
    			user=new EntUser();
    			LepAndMarInfoOfUser lepAndMarInfo = new LepAndMarInfoOfUser();
    			user.setUserType("5");
    			user.setUsername(userName);
    			user.setPassword(MD5Util.createEncryptPSW(userName));
    			if(obj.containsKey("mobilePhone")){
    				user.setTel(obj.getString("mobilePhone"));
        		}
        		if(obj.containsKey("idcard")){
        			user.setElepapernumber(obj.getString("idcard"));
        		}
    			if(obj.getString("registNumber")!=null&& !"".equals(obj.getString("registNumber"))&&(
    	    			BusiMainBodyInfo.BUSITYPE_BG.equals(busiType) ||BusiMainBodyInfo.BUSITYPE_ZX.equals(busiType)
    	    			||BusiMainBodyInfo.BUSITYPE_BA.equals(busiType) ||BusiMainBodyInfo.BUSITYPE_QSZBA.equals(busiType))){
    				user.setUsername(obj.getString("registNumber"));
    				user.setPassword(MD5Util.createEncryptPSW(obj.getString("registNumber")));
					NetMainBody nmb = busiMainBodyInfoService.getNetMainBodyByRegNo(obj.getString("registNumber"));
	                if (nmb == null || nmb.getId()==null) {
	                    throw new RuntimeException("无法找到主体表数据！");
	                } else {
	                	user.setUserFrom(EntUser.USERFROM_ICPSP);
	        			entUserService.save(user);
	        			lepAndMarInfo = lepAndMarInfoService.findLepAndMarInfoByRegNoAndUserType(registNumber, LepAndMarInfoOfUser.USERTYPE_3);
                        if (lepAndMarInfo == null) {
                            lepAndMarInfo = new LepAndMarInfoOfUser();
                        }
	        			lepAndMarInfo = dealLepAndMarInfoData(nmb,lepAndMarInfo,user);
	        			if (lepAndMarInfo.getCerNo()!=null) {
	        				if (lepAndMarInfo.getId()!=null) {
	        					lepAndMarInfoService.updateLepAndMarInfoOfUser(lepAndMarInfo);
		        			} else {
		        				lepAndMarInfoService.saveLepAndMarInfoOfUser(lepAndMarInfo);
		        			}
	        			}else {
	        				throw new RuntimeException("无法找到法定代表人信息！");
	        			}
	                }
    			}else{
    				user.setUsername(userName);
    				user.setPassword(MD5Util.createEncryptPSW(userName));
    				user.setUserFrom(EntUser.USERFROM_ICPSP);
        			entUserService.save(user);
    			}
    		}
			 if (user.getThisTime()==null) {
				 user.setLastTime(new Date());
	         } else {
	        	 user.setLastTime(user.getThisTime());
	         }
			 user.setThisTime(new Date());
			session.setAttribute("entUser", user);
			//如果是已设立企业，说明要办理变更、备案、注销业务
			if(obj.getString("registNumber")!=null&& !"".equals(obj.getString("registNumber"))){
				if(BusiMainBodyInfo.BUSITYPE_BG.equals(busiType)){
					//查询是否有变更信息
					BusiMainBodyInfo infolist = busiMainBodyInfoService.findBusiMainBodyInfoByUserIdAndBusiType(user.getId(), BusiMainBodyInfo.BUSITYPE_BG);
					if(reCreate || infolist==null){
						session.setAttribute("reCreate", true);
					}
					System.out.println("-----------------------LoginAction:reCreate:"+reCreate);
					return "redirect:/alt/flowChoices.action";
				}else if(BusiMainBodyInfo.BUSITYPE_ZX.equals(busiType)){
					return "redirect:/cancel/cancelUI.action";
				}else if(BusiMainBodyInfo.BUSITYPE_BA.equals(busiType)){
					return "redirect:/record/recordUI.action";
				}else if(BusiMainBodyInfo.BUSITYPE_QSZBA.equals(busiType)){
        			return "redirect:/accountRecord/recordUI.action";
        		}else if(BusiMainBodyInfo.BUSITYPE_BM.equals(busiType)){//变名登记
        			return "redirect:/namechange/namechangeUI.action";
        		}
			}
			List<BusiMainBodyInfo> list = busiMainBodyInfoService.findBusiMainBodyInfoByUserId(user.getId());
			boolean userHandleEntForManyFlag = codeService.getSysParameterAsBoolean(SysConstants.UserHandleEntForManyFlag);
        	String ToTopmeims="";
            if(request.getSession().getAttribute("ToTopmeims")!=null){
            	ToTopmeims = (String) request.getSession().getAttribute("ToTopmeims");//孵化员标识
            }
            if("Y".equals(ToTopmeims)){
            	userHandleEntForManyFlag=true;
            }
			if(list!=null && list.size()>0){
				BusiMainBodyInfo bus = list.get(0);
				if(BusiMainBodyInfo.BUSITYPE_MC.equals(bus.getBusiType())){
					if (userHandleEntForManyFlag) {
						return "redirect:/nameAndRegisterList.action";
					}else{
						return "redirect:/namereg/flowChoices.action";
					}
				}else if(BusiMainBodyInfo.BUSITYPE_SL.equals(bus.getBusiType())){
					if (userHandleEntForManyFlag) {
						return "redirect:/nameAndRegisterList.action";
					}else{
						return "redirect:/register/mainBodyUI.action";
					}
				}
			}else{
				if(BusiMainBodyInfo.BUSITYPE_MC.equals(busiType)){
					if (userHandleEntForManyFlag) {
						return "redirect:/nameAndRegisterList.action";
					}else{
						return "redirect:/namereg/flowChoices.action";
					}
				}else if(BusiMainBodyInfo.BUSITYPE_SL.equals(busiType)){
					if (userHandleEntForManyFlag) {
						return "redirect:/nameAndRegisterList.action";
					}else{
						return "redirect:/register/mainBodyUI.action";
					}
				}
			}
			if(obj.getString("registNumber")!=null&& !"".equals(obj.getString("registNumber"))){
				return "redirect:/guideEnt.action";
			}else{
				return "redirect:/guide.action";
			}
    	}else{
    		throw new RuntimeException("读取用户信息失败！");
    	}
    }
    /**
     * 手机号码或者邮箱校验查询
     * @param tel
     * @param email
     * @return
     */
    private String phoneCheck(String tel,String email){
    	StringBuffer msg = new StringBuffer();
    	if(tel!=null&&!"".equals(tel)){
    		EntUser entUser = entUserService.findByTel(tel);
            if(entUser!=null){
            	boolean onlyPhoneCheck = codeService.getSysParameterAsBoolean(SysConstants.onlyPhoneCheck);
	            if(onlyPhoneCheck){
	            	msg.append("手机号码已被使用，请更换手机号码！");
	            }
            }
    	}else if(email!=null&&!"".equals(email)){
    		EntUser entUser = entUserService.findEntUserByEmail(email,"");
    		if(entUser!=null){
    			boolean onlyEmailCheck = codeService.getSysParameterAsBoolean(SysConstants.onlyEmailCheck);
    			if(onlyEmailCheck){
    				msg.append("邮箱已被使用，请更换邮箱！");
    			}
    		}
    	}
    	return msg.toString();
    }
    private String emailCheck(String email,String entId){
    	StringBuffer msg = new StringBuffer();
    	if(email!=null&&!"".equals(email)){
    		EntUser entUser = entUserService.findEntUserByEmail(email,entId);
    		if(entUser!=null){
    				boolean onlyEmailCheck = codeService.getSysParameterAsBoolean(SysConstants.onlyEmailCheck);
        			if(onlyEmailCheck){
        			boolean flag =entUserService.findEntUserByEmailNo(email,entId);//用户信息维护 验证邮箱是否唯一
        			if(flag){
        				msg.append("邮箱已被使用，请更换邮箱！");
        			}
        			}	
    			}
    	}
    	return msg.toString();

    }
    @RequestMapping("/phoneCheck.action")
    @ResponseBody
    public Map<String,String> phoneCheck(HttpServletRequest request, HttpServletResponse response,ModelMap model){
    	Map<String,String> map = new HashMap<String,String>();
    	String tel = request.getParameter("tel");
    	if (tel == null) {
            tel = "";
        } else {
            tel = tel.trim();
        }
    	String phoneError=this.phoneCheck(tel,null);
    	if(phoneError!=null&&!"".equals(phoneError))
    		map.put("error",phoneError);
    	return map;
    }
    @RequestMapping("/emailCheck.action")
    @ResponseBody
    public Map<String,String> emailCheck(HttpServletRequest request, HttpServletResponse response,ModelMap model){
    	Map<String,String> map = new HashMap<String,String>();
    	String email = request.getParameter("email");
    	if (email == null) {
    		email = "";
        } else {
        	email = email.trim();
        }
    	String emailError=this.phoneCheck(null,email);
    	if(emailError!=null&&!"".equals(emailError))
    		map.put("error",emailError);
    	return map;
    }
    @RequestMapping("modifyEmailCheck.action")
    @ResponseBody
    public Map<String,String> modifyEmailCheck(HttpServletRequest request, HttpServletResponse response,ModelMap model){
    	Map<String,String> map = new HashMap<String,String>();
    	String email = request.getParameter("email");
    	String entId = request.getParameter("entId");
    	if (email == null) {
    		email = "";
        } else {
        	email = email.trim();
        }
    	if(entId==null){
        	entId="";
        }else{
        	entId=entId.trim();
        }
    	String emailError=this.emailCheck(email,entId);
    	if(emailError!=null&&!"".equals(emailError))
    		map.put("error",emailError);
    	return map;
    }
    @RequestMapping("modifyEntuser.action")
    public String modifyEntuser(HttpServletRequest request, HttpServletResponse response,ModelMap model){
    	EntUser entUser = (EntUser) request.getSession().getAttribute("entUser");
		if(request.getParameter("phone")!=null&&!"".equals(request.getParameter("phone"))){
			entUser.setTel(request.getParameter("phone"));
		}
		if(request.getParameter("email")!=null&&!"".equals(request.getParameter("email"))){
			entUser.setEmail(request.getParameter("email"));
		}
		if(request.getParameter("name")!=null&&!"".equals(request.getParameter("name"))){
			entUser.setElename(request.getParameter("name"));
		}
		if(request.getParameter("cerno")!=null&&!"".equals(request.getParameter("cerno"))){
			entUser.setElepapernumber(request.getParameter("cerno"));
		}
		if(request.getParameter("certype")!=null&&!"".equals(request.getParameter("certype"))){
			entUser.setElepaper(request.getParameter("certype"));
		}
    	String str="success";
    	entUserService.update(entUser);
        Certification certification = busService.getByPaperNum(entUser.getElepapernumber());
        if(certification!=null && certification.getId()!=null ){
            certification.setPhone(request.getParameter("phone"));
            busService.update(certification);
        }
    	return "redirect:/toUserCenter.action?success="+str;
    }

    @RequestMapping("checkPhoneCode.action")
    @ResponseBody
    public  Map<String,String> checkPhoneCode(HttpServletRequest request, HttpServletResponse response,ModelMap model){
    	 String tel = request.getParameter("phone");
    	 String phoneCode=request.getParameter("phonecode");
    	 String error = "";
    	 Map<String,String> map = new HashMap<String,String>();
    	//允许在演示或者测试环境下不验证验证码
         String portStr = request.getServerPort()+"";
         String notlogin = codeService.getSysParameter("notlogin");
         if((!Strings.isNullOrEmpty(notlogin))&&(notlogin.equals("Y") && (portStr.equals("9080") || portStr.equals("9081") || portStr.equals("9082") || portStr.equals("9083") || portStr.equals("9088")))
         		|| (!"".equals(portStr)&&notlogin.contains(portStr))){
        	 	map.put("error", "");
      			return map;
         }
    	 String validity = codeService.getSysParameter(SysConstants.VERICODEVALIDITYCONFIG);
    	 map.put("error", error);
         int effecTime = 5;
         if (validity != null && !"".equals(validity)) {
             effecTime = Integer.parseInt(validity);
         }
         List<DynamicPD> dynPDList = mesgService.findDynamicPDByEnUserTelAndNow(tel, new Date(), effecTime);
         if (dynPDList == null || dynPDList.size() <= 0) {
             LoginLog loginLog = new LoginLog();
             loginLog.setEnUserID(Long.parseLong(tel));
             loginLog.setCreateDate(new Date());
             loginLog.setState(LoginLog.LOGINFAILED);
             mesgService.saveLoginLog(loginLog);
             DynamicPD dPD = mesgService.findDynamicPDByEnUserTelAndPD(tel, phoneCode);
             if (dPD != null && dPD.getId() != null) {
                 error = "手机验证码已失效！";
             } else {
                 error = "手机验证码错误！";
             }
             map.put("error", error);
         } else {
             DynamicPD dynamicPD = dynPDList.iterator().next();
             if (!dynamicPD.getDynamicPD().equals(phoneCode)) {
                 LoginLog loginLog = new LoginLog();
                 loginLog.setEnUserID(Long.parseLong(tel));
                 loginLog.setCreateDate(new Date());
                 loginLog.setState(LoginLog.LOGINFAILED);
                 mesgService.saveLoginLog(loginLog);
                 error = "手机验证码错误！";
                 map.put("error", error);
             }
         }
         return map;
    }
    @RequestMapping("checkUserInfo.action")
    @ResponseBody
    public String checkUserInfo(HttpServletRequest request,HttpServletResponse response,String userName,String tel){
    	boolean phoneLoginFlag=codeService.getSysParameterAsBoolean(SysConstants.PHONELOGINFLAG);
    	EntUser entUser = entUserService.findByUsername(userName,phoneLoginFlag);
    	if(entUser!=null){
    		if(tel!=null&&!"".equals(tel)&&tel.equals(entUser.getTel())){
    			return "true";
    		}
    		return "false";
    	}else{
    		return "noEntUser";
    	}
    }
    @RequestMapping("/checkPhoneInfo.action")
    @ResponseBody
    public String checkPhoneInfo(HttpServletRequest request, HttpServletResponse response, ModelMap model) throws UnsupportedEncodingException{
    	String username=request.getParameter("username");
    	String elename = request.getParameter("elename");
    	if(elename!=null&&!"".equals(elename)){
    		elename = URLDecoder.decode(elename,"utf-8");
    	}
    	String elepapernumber=request.getParameter("elepapernumber");
    	String tel=request.getParameter("tel");
    	String email=request.getParameter("email");
    	boolean phoneLoginFlag=codeService.getSysParameterAsBoolean(SysConstants.PHONELOGINFLAG);
    	EntUser entUser = entUserService.findByUsername(username,phoneLoginFlag);
    	String type = request.getParameter("type");
    	String str="";
    	if(entUser!=null){
    		if(elename!=null&&!elename.equals(entUser.getElename())){
    			str+="2";
    		}
    		if(elepapernumber!=null&&!elepapernumber.equals(entUser.getElepapernumber())){
    			str+="3";
    		}
    		if(tel!=null&&!tel.equals(entUser.getTel())){
    			str+="4";
    		} 
    		if(email!=null&&!email.equals(entUser.getEmail())){
    			str+="5";
    		}
    		if(type!=null){
    			if(type.equals("cfca") &&entUser.getCerDN()==null){ 
    				str+="6";
    			}
//    			else if("sj".equals(type)&&!"2".equals(entUser.getUserType())){
//    				str+="7";
//    			}
    		}
    		if(!str.equals("")){
    			return str;
    		}
    		return "true";
    	}else{
    		return "1";
    	}
    }
    @RequestMapping("/allForgetSave.action")
    public String allForgetSave(HttpServletRequest request, HttpServletResponse response,ModelMap model,
    		String issuerDN,String signMsg,String cerSerialNo){
    	model.put("bLicTypes", codeService.getAllBLicTypeCode());
    	boolean isShowCerType = codeService.getSysParameterAsBoolean(SysConstants.isShowCerType);
    	model.put("isShowCerType",isShowCerType);
    	model.put("cerTypes", codeService.getAllCertificateTypeCode());
    	//boolean isSendSms = codeService.getSysParameterAsBoolean(SysConstants.isSendSms);
    	model.put("location", "忘记密码");
    	String password = request.getParameter("password");
    	String elename = request.getParameter("elename");
    	String elepapernumber = request.getParameter("elepapernumber");
    	//手机号码
    	String tel = request.getParameter("mobilePhone");
//    	String newEnt = request.getParameter("newEnt");
		//邮箱账号
		String email = request.getParameter("email");
		
		String error = null;
    	boolean isSame = true;
		
		List<EntUser> entUserList =  null;
		if(elename!=null&&!elename.equals("")){
			//个人用户 原始密码方式  通过用户姓名，证件号码，手机号码 获取当前用户信息
			entUserList=entUserService.findEntUserByTelAndEleNumber(elename, elepapernumber, tel);	
		}else{
			if(tel!=null&&!tel.equals("")){
				//个人用户 通过手机号获取用户
				entUserList=entUserService.findEntUserByTelAndCerNo(tel, elepapernumber);	
			}
			if(email!=null&&!email.equals("")){
				//个人用户 通过邮箱号获取用户
				entUserList=entUserService.findEntUserByEmailNoAndCerNo(email, elepapernumber);	
			}
		}
		if(entUserList==null || entUserList.size()<=0){
			isSame = false;
		}
		/*else{
				if(elename==null||elename.equals("")){
					if(tel!=null&&!tel.equals("")&&!tel.equals(entUser.getTel())){
        				isSame = false;
    			}
    			
    			if(email!=null&&!email.equals("")&&!email.equals(entUser.getEmail())){
    				isSame = false;
    			}	
				}
		}*/
		
    	if(!isSame){
    		error="用户验证失败，请确认后再次重置密码！";
    	}
    	if(error==null||"".equals(error)){
    		String newPsw="";
    			if(elename==null || elename.equals("")){
    				//生成6位密码
           		 newPsw= Util.getRandomPSW(6);	
    			}else{
    				newPsw=password;
    			}
    		
    			 String userNameList = null;//多个用户名拼接
	        		if(entUserList.size()>0){
	        			for(int i=0;i<entUserList.size();i++){
	        				EntUser entUser = entUserList.get(i);
	        				if(i==0){
	        					userNameList=entUser.getUsername();
	        				}else{
	        					userNameList+="，"+entUser.getUsername();
	        				}
	        			}
	        		}
    			
    			if(elename==null || elename.equals("")){
    				if(tel!=null&&!tel.equals("")){
        	    		//短信接口
        	    		try {
        	    			//拼接短信内容START--
        	    			String smsContentConfig = codeService.getSysParameter(SysConstants.forgotPwdPhoneMsgConfig);
        	    			Calendar cal = Calendar.getInstance();
        	                int year = cal.get(Calendar.YEAR);// 获取年份
        	                int month = cal.get(Calendar.MONTH) + 1;// 获取月份
        	                int day = cal.get(Calendar.DATE);// 获取日
        	                int hour = cal.get(Calendar.HOUR_OF_DAY);
        	                int minute = cal.get(Calendar.MINUTE);
        	                int seconds = cal.get(Calendar.SECOND);
        	                
        	               // String time = new SimpleDateFormat("yyyymmddHHMMss").format(new Date());
        	                smsContentConfig = smsContentConfig.replace("yyyy", year + "");
        	                smsContentConfig = smsContentConfig.replace("mm", month + "");
        	                smsContentConfig = smsContentConfig.replace("dd", day + "");
        	                smsContentConfig = smsContentConfig.replace("hh", hour + "");
        	                smsContentConfig = smsContentConfig.replace("MM", minute + "");
        	                smsContentConfig = smsContentConfig.replace("ss", seconds + "");
        	               
        	        		smsContentConfig = smsContentConfig.replace("userName", userNameList); 
        	        		smsContentConfig = smsContentConfig.replace("newPwd", newPsw);
        	   		    //拼接短信内容end--
        	    			SendMessageUtil.sendMsg(tel, smsContentConfig);//发送短信内容
        	    			//保存短信内容
        	    			SmsRecord smsRecord=new SmsRecord();
        	    			smsRecord.setContext(smsContentConfig);
        	    			smsRecord.setSendDate(new Date());
        	    			smsRecord.setTel(tel);
        	    			busiMainBodyInfoService.createSmsRecord(smsRecord);
        				} catch (Exception e) {
        					throw new RuntimeException("短信发送失败！");
        				}	
        	    		}else if(email!=null&&!email.equals("")){
        	    			//邮件内容拼接START---
        	    			String mailContent = codeService.getSysParameter(SysConstants.forgotPwdEmailMsgConfig);
        	                Calendar cal = Calendar.getInstance();
        	                int year = cal.get(Calendar.YEAR);// 获取年份
        	                int month = cal.get(Calendar.MONTH) + 1;// 获取月份
        	                int day = cal.get(Calendar.DATE);// 获取日
        	                int hour = cal.get(Calendar.HOUR_OF_DAY);
        	                int minute = cal.get(Calendar.MINUTE);
        	                int seconds = cal.get(Calendar.SECOND);
        	               // String time = new SimpleDateFormat("yyyymmddHHMMss").format(new Date());
        	                mailContent = mailContent.replace("yyyy", year + "");
        	                mailContent = mailContent.replace("mm", month + "");
        	                mailContent = mailContent.replace("dd", day + "");
        	                mailContent = mailContent.replace("hh", hour + "");
        	                mailContent = mailContent.replace("MM", minute + "");
        	                mailContent = mailContent.replace("ss", seconds + "");
        	                mailContent = mailContent.replace("userName", userNameList);
        	                mailContent = mailContent.replace("newPwd", newPsw);
        	                
        	              //邮件内容拼接END---
        	               // mailContent="温馨提示：您的登录密码为"+newPsw;
        	    		   //邮箱接口
        	    			 MailSenderInfo mailInfo = new MailSenderInfo();
        	                 String mailServerHost=codeService.getSysParameter(SysConstants.MAILSERVERHOST);
        	                 String mailServerPort=codeService.getSysParameter(SysConstants.MAILSERVERPORT);
        	                 mailInfo.setMailServerHost(mailServerHost);
        	                 mailInfo.setMailServerPort(mailServerPort);
        	                 mailInfo.setValidate(true);
        	                 String username=codeService.getSysParameter(SysConstants.USERNAME);
        	                 String email_pwd=codeService.getSysParameter(SysConstants.PASSWORD);
        	                 //test
        	                 String mailSubject="工商网上业务密码找回";
        	                 //String mailSubject=codeService.getSysParameter(SysConstants.MAILSUBJECT);

        	                 // 邮箱用户名
        	                 mailInfo.setUserName(username);
        	                 // 邮箱密码
        	                 mailInfo.setPassword(email_pwd);
        	                 // 发件人邮箱
        	                 mailInfo.setFromAddress(username);
        	                 // 收件人邮箱
        	                 mailInfo.setToAddress(email);
        	                 // 邮件标题
        	                 mailInfo.setSubject(mailSubject);
        	                 // 邮件内容
        	                 mailInfo.setContent(mailContent);
        	                 // 发送邮件
        	                 SimpleMailSender sms = new SimpleMailSender();
        	                 // 发送文体格式
        	                 sms.sendHtmlMail(mailInfo);
        	                 //邮件内容保存
        	                 EmailRecord emailRecord=new EmailRecord();
        	                 emailRecord.setContext(mailContent);
        	                 emailRecord.setSendDate(new Date());
        	                 emailRecord.setEmail(email);
         	    			busiMainBodyInfoService.createEmailRecord(emailRecord);
        	                 System.out.println("邮件发送完毕");	
        		}	
    			}
    		if(entUserList.size()>0){
    			for(int i=0;i<entUserList.size();i++){
    				EntUser entUser = entUserList.get(i);
    				entUser.setPassword(MD5Util.createEncryptPSW(newPsw));
            		entUserService.update(entUser);
    			}
    			if(elename!=null&&!elename.equals("")){
        			model.put("register","用户名为"+userNameList+"的密码重置成功！");
        		}else{
        			model.put("register","密码重置成功！");	
        		}
    		}
    	}else{
    		model.put("register",error);
    	}
    	return "/template/login/newAllForgetPwd.html";
    }
    @RequestMapping("/realNameAuthSave.action")
    @ResponseBody
    public Map<String,Object> realNameAuthSave(HttpServletRequest request,HttpServletResponse response,ModelMap model) throws Exception{
    	response.setContentType("text/html;charset=UTF-8");
   	 	response.setHeader("Content-Type","text/html");
    	Map<String,Object> result = new HashMap<String,Object>();
    	String paper = request.getParameter("paper");
    	String name = request.getParameter("name");
    	String paperNumber = request.getParameter("paperNumber");
    	String authType = request.getParameter("authType");
    	String cerDN = request.getParameter("cerDN");
    	String bankNumber = request.getParameter("bankNumber");
    	String phone = request.getParameter("phone");
    	String signMsg = request.getParameter("signMsg");
    	String cerSerialNo = request.getParameter("cerSerialNo");
    	String issuerDN = request.getParameter("issuerDN");
    	
    	MultipartFile fileFront=null;
    	MultipartFile fileOpposite=null;
    	MultipartFile fileHand=null;
    	String registerFlag = request.getParameter("registerFlag");
    	if(StringUtils.equals(registerFlag, "true")){
    		paper = request.getParameter("elepaper");
    		name = request.getParameter("elename");
        	paperNumber = request.getParameter("elepapernumber");
        	authType = request.getParameter("authType");
        	cerDN = request.getParameter("cerDN");
        	bankNumber = request.getParameter("bankNumber");
        	phone = request.getParameter("tel");
        	signMsg = request.getParameter("signMsg");
        	cerSerialNo = request.getParameter("cerSerialNo");
        	issuerDN = request.getParameter("issuerDN");
        	
    	}
    	String msg = null;
    	boolean isAuthBank = codeService.getSysParameterAsBoolean(SysConstants.isAuthBank);//演示环境不真正进行银行卡校验
    	if("1".equals(authType)){
    		msg = this.CARegisterSave(name, paperNumber, paper, model, issuerDN, signMsg, cerSerialNo);
    	}else if(!isAuthBank&&"2".equals(authType)){
    		String authWay = codeService.getSysParameter(SysConstants.authWay);
    		String str = bankRealNameCheck(request,response,name, paper, paperNumber, phone, bankNumber,authWay);
    		if(str==null||"".equals(str)||(!str.startsWith("{")&&!str.endsWith("}"))){
				msg = "实名认证失败，银行认证系统网络连接失败，请联系工商管理人员！";
    		}else{
    			JSONObject json = JSONObject.fromObject(str);
    			String responseCode = null;
    			try{
					responseCode=json.getString("respCode");
    			}catch(JSONException e){
    				responseCode = null;
    			}
    			if(responseCode!=null&&!"".equals(responseCode)){
    				if("tn020".equals(responseCode)){
    					msg = "实名认证失败，"+json.getString("respMsg")+"！";
    				}else{
    					msg = "实名认证失败，原因："+json.getString("respMsg")+"！";
    				}
    			}
    		}
    	}else if("3".equals(authType)){
    		String smrz_policWay = codeService.getSysParameter(SysConstants.smrz_policWay);
    		if("01".equals(smrz_policWay)){//河南公安
    			boolean realNameSMRZ = codeService.getSysParameterAsBoolean(SysConstants.realNameSMRZ);
	    		//不使用扫码认证
	    		if(!realNameSMRZ){
		    		// 转型为MultipartHttpRequest：
		        	MultipartHttpServletRequest multipartRequest = (MultipartHttpServletRequest) request; 
		    		// 获得文件：
		    		 fileFront = multipartRequest.getFile("fileFront");
		    		 fileOpposite = multipartRequest.getFile("fileOpposite");
		    		 fileHand = multipartRequest.getFile("fileHand");
		    		
		//    		String endTime=request.getParameter("endTime");
		//    		String address=request.getParameter("address");
		    		msg=this.realNamePolic(paperNumber,fileHand);
	    		}else{
	    			result.put("success", true);
	        		result.put("msg", "实名认证成功！");
	        		return result;
	    		}
    		}else if("02".equals(smrz_policWay)){//西藏公安
    			msg = this.realNamePolic_xz(request, paperNumber, name);
    		}
    	}
    	if(msg==null||"".equals(msg)){
    		if(fileFront!=null&&fileOpposite!=null&&fileHand!=null){
    		IdCard idCard = datumService.findIdCardCernos(paperNumber, IdCard.ZJLX_S);
    		if(idCard==null){
    			idCard = new IdCard();
    		}
    		//文件size
    		Integer size= (int)(fileFront.getSize()+fileOpposite.getSize()+fileHand.getSize());
    		
    		idCard.setContentZm(fileFront.getBytes());		
    		idCard.setContentFm(fileOpposite.getBytes());
    		idCard.setContentSc(fileHand.getBytes());	
    		idCard.setCerno(paperNumber);//证件号码
    		idCard.setCertype(IdCard.Type_A);//证件类型
    		idCard.setCreatedate(new Date());
    		idCard.setModifydate(new Date());
    		idCard.setSize(size);
    		idCard.setType(IdCard.Type_Z);
    		idCard.setZzlx(IdCard.ZJLX_S);
    		if(idCard.getId()==null){
    			idCard.setId(busiMainBodyInfoService.getSeq());
        		//保存
        		service.creatIdCard(idCard);
    		}else{
    			service.updateIdCard(idCard);
    		}
    		}
    		
	    	Certification certification = busService.getByPaperNum(paperNumber);
	    	if(certification==null){
	    		certification = new Certification();
	    	}
	    	certification.setName(name);
	    	certification.setPaper(paper);
	    	certification.setPaperNumber(paperNumber.toUpperCase());
	    	certification.setPhone(phone);
	    	certification.setAuthType(authType);
	    	certification.setCerDN(cerDN);
	    	certification.setIssuerDN(issuerDN);
	    	certification.setCerSerialNo(cerSerialNo);
	    	certification.setSendMsg(signMsg);
	    	//certification.setBankNumber(bankNumber);
	    	
    		certification.setAuthFlag("1");
    		if(Strings.isNullOrEmpty(certification.getApplySign())){
    			certification.setApplySign("0");
    		}
    		if(Strings.isNullOrEmpty(certification.getApplyType())){
    			certification.setApplyType("1");
    		}
    		Date nowDate = new Date();
    		certification.setTimestamp(nowDate);
    		if(certification.getApplyNum()==0){
    			certification.setApplyNum(0);
    		}
    		if(certification.getId()==null){
    			certification.setCreateDate(nowDate);
    			certification.setId(busiMainBodyInfoService.getSeq());
    			busService.save(certification);
    		}else{
    			busService.update(certification);
    		}
//    		List<EntUser> entUserList  =  entUserService.findEntUserByNewEntAndEleNumber(certification.getPaperNumber());
//            if (entUserList!=null && entUserList.size()>0) {
//                EntUser entUser = entUserList.get(0);
//                entUser.setTel(certification.getPhone());
//                entUserService.update(entUser);
//            }
    		result.put("success", true);
    		result.put("msg", "实名认证成功！");
    	}else{
    		if("false".equals(msg)){
        		msg="实名认证失败，用户信息与数字证书不匹配！";
    		}else if("error".equals(msg)){
    			msg="实名认证失败，请稍候进行实名认证！";
    		}
    		result.put("success", false);
    		result.put("msg", msg);
    	}
    	return result;
    }
    /**
     * 
     * @Title:        title
     * @Description:  公安机关认证
     * @param request
     * @param name
     * @param paperNumber
     * @return    
     * @version       V2.1
     * @author        wuwanran
     * @throws IOException 
     * @Date          2017年9月13日 下午4:14:54
     */
    public String realNamePolic(String paperNumber,MultipartFile fileHand) throws IOException{
		Date time = new Date();
		SimpleDateFormat sdf = new SimpleDateFormat("yyyy-M-d HH:mm:ss");
		String timeFormat= sdf.format(time);//图片拍摄时间
		InputStream in = fileHand.getInputStream();
		String hImageType = fileHand.getOriginalFilename().substring(fileHand.getOriginalFilename().lastIndexOf(".")+1);
		int size = (int) fileHand.getSize();
		float quality= (float) 0.7;
		byte[] fileByte = ImageReduce.getImgWHScale(in,500,500,quality,true,hImageType,size);
		System.out.println("压缩前大小====="+size+"压缩后大小====="+fileByte.length);
		BASE64Encoder encoder = new BASE64Encoder();  
		String HImageData = encoder.encode(fileByte);
		JSONObject json = new JSONObject();
		json.element("IDType","1");//身份证
		json.element("IDNumber",paperNumber);//身份证号
		json.element("CapTime",timeFormat);//图片拍摄时间
		json.element("ImageType", hImageType);//本人照片类型
		json.element("ImageData",HImageData);//对应图像文件二进制数据的base64编码反面
		json.element("UserCode","10001");//调用接口的
		json.element("DevLongitude","");//采集设备所在位置的经度。没有可以空着
		json.element("DevLatitude","");//采集设备所在位置的纬度。没有可以空着
		json.element("DevCode","001001");//采集设备代码
        String url = "http://www.baidu.com";//初始化路径
        url= codeService.getSysParameter(SysConstants.policUrl);
        CloseableHttpClient httpclient = HttpClientBuilder.create().build();
        HttpPost post = new HttpPost(url);
        String str = null;
        try {
            StringEntity s = new StringEntity(json.toString());
            s.setContentEncoding("UTF-8");
            s.setContentType("application/json");//发送json数据需要设置contentType
            post.setEntity(s);
            HttpResponse res = httpclient.execute(post);
            if(res.getStatusLine().getStatusCode() == HttpStatus.SC_OK){
                str = EntityUtils.toString(res.getEntity());// 返回json格式：
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        
		System.out.println("返回结果++++++++"+str);
		JSONObject jsonObject = JSONObject.fromObject(str);
		String retStatus="";
		String retInfo="";//
		String nResult="";//0 正常，其他失败
		String sError="";//错误描述
		String samePerson="";//YES 表示是同一人NO 表示不是同一人
//		String value="";//人像的相似度
		try{
			retStatus=jsonObject.getString("RetStatus");
			retInfo = jsonObject.getString("RetInfo");
			JSONObject retStatusObject = JSONObject.fromObject(retStatus);
			JSONObject retInfoObject = JSONObject.fromObject(retInfo);
			nResult=retStatusObject.getString("nResult");
			sError=retStatusObject.getString("sError");
			System.out.println("是否成功+++++++++"+nResult);
			if("0".equals(nResult)){
				samePerson=retInfoObject.getString("SamePerson");
//				value=retStatusObject.getString("Value");
				//认证成功
				System.out.println("是否同一人+++++++++"+samePerson);
			}else{
				System.out.println("错误描述+++++++++++++"+sError);
				return sError;
			}
			if("YES".equals(samePerson)){
				return "";
			}else{
				return "身份证与本人不符";
			}
		}catch(JSONException e){
			e.fillInStackTrace();
		}
		return "error";
       
    }
    @RequestMapping("/validEleNumber.action")
    @ResponseBody
    public boolean validEleNumber(String elePaperNumber){
    	boolean flag = false;
    	List<EntUser> users = entUserService.findEntUserByNewEntAndEleNumber(elePaperNumber);
    	if(users!=null){
    		flag = true;
    	}
    	return flag;
    }
    @RequestMapping("/realNameAuthCheck.action")
    @ResponseBody
    public Map<String,Object> realNameAuthCheck(HttpServletRequest request, HttpServletResponse response, ModelMap model) throws IOException{
    	Map<String,Object> map = new HashMap<String,Object>();
    	String name = request.getParameter("name");
    	if(StringUtils.isNotEmpty(name)){
    		name = URLDecoder.decode(name,"UTF-8").trim();
    	}else{
    		name="";
    	}
    	String paper = request.getParameter("paper");
    	String paperNumber = request.getParameter("paperNumber");
    	if(paperNumber!=null&&!"".equals(paperNumber)){
    		paperNumber=URLDecoder.decode(paperNumber,"UTF-8").trim();
    	}else if(paperNumber==null){
    		paperNumber = "";
    	}
    	String flag = request.getParameter("flag");
    	int amount = 60;//默认60分钟
    	String validiteTime = codeService.getSysParameter(SysConstants.validiteTime);
    	if(StringUtils.isNotEmpty(validiteTime)){
    		amount = Integer.parseInt(validiteTime);
    	}
    	Certification certification = busService.getByPaperNum(paperNumber);
    	if(certification!=null){
    		map.put("realName", true);
    		boolean isValidity = true;
    		if(certification.getTimestamp()!=null){
    			isValidity = compareTime(certification.getTimestamp(),new Date(),amount);//是否在有效期中，true是
    		}else{
    			isValidity = false;
    		}
    		if(StringUtils.equals(certification.getApplySign(), "1")){//如果是若证书申请通过后，默认为有效，
    			isValidity = true;
    		}
    		if(!StringUtils.equals(name, certification.getName())||!StringUtils.equals(paper, certification.getPaper())){
    			map.put("realNameError", true);
    		}else{
	    		if(flag!=null&&"apply".equals(flag)){
		    		if(StringUtils.equals(certification.getApplySign(), "1")){
		    			map.put("applySign", true);
		    		}else{
			    		if(isValidity){
		    				map.put("applySign", false);
			    		}else{
			    			map.put("unValidity", true);
			    		}
		    		}
	    		}
    		}
    	}else{
    		map.put("realName", false);
    	}
    	return map;
    }
    @RequestMapping("/applyCancel.action")
    @ResponseBody
    public Map<String,Object> applyCancel(HttpServletRequest request, HttpServletResponse response, ModelMap model) throws IOException{
    	Map<String,Object> map = new HashMap<String,Object>();
    	String paperNumber = request.getParameter("paperNumber");
    	if(paperNumber!=null&&!"".equals(paperNumber)){
    		paperNumber=java.net.URLDecoder.decode(paperNumber,"UTF-8").trim();
    	}else if(paperNumber==null){
    		paperNumber = "";
    	}
    	Certification certification = busService.getByPaperNum(paperNumber);
    	if(certification!=null){
			certification.setApplySign("0");
    		busService.update(certification);
    		map.put("success", true);
    	}else{
    		map.put("success", false);
    	}
    	return map;
    }
    @RequestMapping("/realNameAuthUpdate.action")
    @ResponseBody
    public Object realNameAuthUpdate(HttpServletRequest request, HttpServletResponse response, ModelMap model) throws IOException{
    	Map<String,Object> map = new HashMap<String,Object>();
    	String paperNumber = request.getParameter("paperNumber");
    	String applySign = request.getParameter("applySign");
    	System.out.println("证件号码："+paperNumber+"；申请标志："+applySign);
    	if(paperNumber!=null&&!"".equals(paperNumber)){
    		paperNumber=java.net.URLDecoder.decode(paperNumber,"UTF-8").trim();
    	}else if(paperNumber==null){
    		paperNumber = "";
    	}
    	Certification certification = busService.getByPaperNum(paperNumber);
    	if(certification!=null){
    		if(applySign!=null&&"1".equals(applySign)){
    			certification.setApplySign(applySign);
	    		int num = certification.getApplyNum()+1;
	    		certification.setApplyNum(num);
    		}else{
    			certification.setApplySign("0");
    		}
    		busService.update(certification);
    		map.put("success", true);
    	}else{
    		map.put("success", false);
    	}
    	JSONObject jsonObject = JSONObject.fromObject(map);
    	return jsonObject;
    }
    public static String md5(String str) {
    	try {
	    	MessageDigest md = MessageDigest.getInstance("MD5");
	    	md.update(str.getBytes("UTF-8"));
	    	byte b[] = md.digest();
	    	int i;
	    	StringBuffer buf = new StringBuffer();
	    	for (int offset = 0; offset < b.length; offset++) {
		    	i = b[offset];
		    	if (i < 0)
		    		i += 256;
		    	if (i < 16)
		    		buf.append("0");
	    			buf.append(Integer.toHexString(i));
	    	}
	    	return buf.toString().toUpperCase();
    	} catch (NoSuchAlgorithmException e) {
    		return null;
    	} catch (UnsupportedEncodingException e) {
    		return null;
    	} catch (Exception e){
    		return null;
    	}
	}
    private String bankRealNameCheck(HttpServletRequest request,HttpServletResponse response,String name,String paper,String paperNumber,String phone,String bankNumber,String authWay){
    	String bankRealNameUrl = codeService.getSysParameter(SysConstants.bankRealNameUrl);
    	if(Strings.isNullOrEmpty(bankRealNameUrl)){
    		bankRealNameUrl = "http://" + request.getServerName() + ":" + request.getServerPort() + "" + request.getContextPath();
    	}
//    	bankRealNameUrl = "http://192.168.3.112:9084/main1_Psp";
    	bankRealNameUrl+="/bankRealNameCheck.action";
    	Map<String,String> params = new HashMap<String,String>();
    	BASE64Encoder encoder = new BASE64Encoder();
    	if(StringUtils.isNotEmpty(name)){
    		try {
				name=encoder.encode(name.getBytes("utf-8"));
			} catch (UnsupportedEncodingException e) {
				e.printStackTrace();
				name="";
			}
    	}else{
    		name="";
    	}
    	
    	params.put("name", name);
    	params.put("paper", paper);
    	params.put("paperNumber", paperNumber);
    	params.put("phone", phone);
    	params.put("bankNumber", bankNumber);
    	String timestamp = System.currentTimeMillis()+"";
    	params.put("timestamp", timestamp);
    	params.put("authWay", authWay);
    	String mac = "authWay="+authWay+"name="+name+"paper="+paper+"paperNumber="+paperNumber+
    			"phone="+phone+"bankNumber="+bankNumber+"timestamp"+timestamp+"&topnetBankCheck";
    	params.put("mac", MD5Util.md5Encryption(mac));
		HttpClientUtil httpClientUtil = new HttpClientUtil();
		String str = httpClientUtil.doPost(bankRealNameUrl, params, "utf-8");
		System.out.println("***"+str+"***");
    	return str;
    }
    @RequestMapping("/sendBankVerCode.action")
    @ResponseBody
    public Map<String, Object> sendBankVerCode(HttpServletRequest request, HttpServletResponse response, ModelMap model) throws Exception {
        Map<String,Object> map = new HashMap<String, Object>();
        String bankUrl = codeService.getSysParameter(SysConstants.bankUrl);
    	String app_id = codeService.getSysParameter(SysConstants.bank_app_id);
    	String api_secret = codeService.getSysParameter(SysConstants.bank_api_secret);
    	bankUrl = bankUrl + "/openbank/api/finance/applySMSSend";
        String phone = request.getParameter("phone");
        Map<String,String> params = new HashMap<String,String>();
		String curTime = System.currentTimeMillis()+"";
		params.put("app_id", app_id);
		params.put("qtxtddh", phone+curTime);
		params.put("mobile", phone);
		params.put("timestamp", curTime);
		String macStr = "app_id"+app_id+"mobile"+phone+"qtxtddh"+phone+curTime+"timestamp"+curTime+api_secret;
		String mac = md5(macStr);
		params.put("mac", mac);
		System.out.println(bankUrl);
		HttpClientUtil httpClientUtil = new HttpClientUtil();
		String str = httpClientUtil.doPost(bankUrl, params, "utf-8");
		System.out.println(str);
		if(str==null||"".equals(str)){
			map.put("success", false);
			map.put("msg", "短信发送失败！");
		}else{
			JSONObject json = JSONObject.fromObject(str);
			String errCode = null;
			try{
				errCode = json.getString("errCode");
			}catch(JSONException e){
				errCode = "";
			}
			if(errCode!=null&&!"".equals(errCode)){
				map.put("success", false);
				map.put("msg", "短信发送失败，原因："+json.getString("errMsg")+"！");
			}else{
				map.put("success", true);
				map.put("msg", "短信发送成功！");
			}
		}
        return map;
    }
    @RequestMapping("/telVerCodeCheck.action")
    @ResponseBody
    public Map<String, Object> telVerCodeCheck(HttpServletRequest request, HttpServletResponse response, ModelMap model) throws Exception {
        Map<String,Object> map = new HashMap<String, Object>();
        String tel = request.getParameter("tel");
        if (tel == null) {
            tel = "";
        } else {
            tel = java.net.URLDecoder.decode(tel, "UTF-8");
            tel = tel.trim();
        }
        String paperNumber = request.getParameter("paperNumber");
        if(paperNumber!=null&&!"".equals(paperNumber)){
        	Certification certification = busService.getByPaperNum(paperNumber);
        	if(!(certification!=null&&tel.equals(certification.getPhone()))){
        		map.put("success", false);
        		map.put("msg", "手机号码与实名认证时录入的不匹配！");
        		return map;
        	}
        }
        String telCode = request.getParameter("telCode");
        if(telCode==null){
        	telCode="";
        }
        //允许在演示或者测试环境下不验证验证码
        String portStr = request.getServerPort()+"";
        String notlogin = codeService.getSysParameter("notlogin");
        if((!Strings.isNullOrEmpty(notlogin))&&(notlogin.equals("Y") && (portStr.equals("9080") || portStr.equals("9081") || portStr.equals("9082") || portStr.equals("9083") || portStr.equals("9088")))
        		|| (!"".equals(portStr)&&notlogin.contains(portStr))){
        	map.put("success", true);
            return map;
        }

        int dynPDNum = mesgService.findDynamicPDCountByEnUserTelAndToday(tel, new Date());
        if (dynPDNum == 0) {
        	map.put("success", false);
        	map.put("msg", "请先获取备案手机验证码！");
            return map;
        }
        String msg = this.phoneRegister(request, response, tel, telCode);
        if(msg!=null&&!"".equals(msg)){
        	map.put("success", false);
        	map.put("msg", msg);
        }else{
        	map.put("success", true);
        }
        return map;
    }
    /**
     * CFCA注册校验
     * @param entUser
     * @param model
     * @param issuerDN
     * @param signMsg
     * @param cerSerialNo
     * @throws Exception
     */
    private String CARegisterSave(String elename,String elepapernumber,String cerType,ModelMap model,String issuerDN,String signMsg,String cerSerialNo){
    
	    	if (cerType!= null && cerType.equals("10")) {
	            cerType = "0";//系统中的身份证1对应认证系统中的身份证代码0
	        } else if (cerType != null && cerType.equals("30")) {
	            cerType = "A";//系统中的警官证3对应认证系统中的警官证A
	        } else if (cerType != null && cerType.equals("40")) {
	            cerType = "1";//系统中的护照4对应认证系统中的护照1
	        } else if (cerType != null && cerType.equals("90")) {
	            cerType = "Z";//系统中的护照4对应认证系统中的其他Z
	        }
        System.out.println("============issuerDN==========="+issuerDN);
        System.out.println("============signMsg==========="+signMsg);
        String cfcaUrl = codeService.getSysParameter("cfcaUrl");
        try {
            int connectTimeout = 3000;
            int readTimeout = 30000;
            
            AuthenticateVO authenticateVO = new AuthenticateVO();
            Signature sigUtil = new Signature();
            JCrypto.getInstance().initialize(JCrypto.JSOFT_LIB, null);
            Session session = JCrypto.getInstance().openSession(JCrypto.JSOFT_LIB);
            if (sigUtil.p7VerifyMessageAttach(signMsg.getBytes("utf-8"), session)) {
                authenticateVO.setTxCode("02001");
                authenticateVO.setSubscriberName(elename);
                authenticateVO.setIdentificationTypeCode(cerType);
                //目前只有身份证类型，证件号码前加0
                authenticateVO.setIdentificationNo(elepapernumber);
                authenticateVO.setSerialNo(cerSerialNo);
                authenticateVO.setIssuerDn(issuerDN);
                authenticateVO.setQueryCertStatus("true");
                authenticateVO.setValidateIdentTypeCode("false");
            } else {
                return "数字证书签名认证失败，请查证！";
            }
            UAClient client = new UAClient(cfcaUrl, connectTimeout, readTimeout);
            SubscriberVO subscriberVO = (SubscriberVO) client.process(authenticateVO);
            System.out.println(subscriberVO.getResultCode());
            System.out.println(subscriberVO.getResultMessage());
            if(UAClient.SUCCESS.equals(subscriberVO.getResultCode())){
                if (subscriberVO.getStatus().equals("0")) {
                    return null;
                } else {
                     if(subscriberVO.getStatus().equals("1")){
                    	 return "数字证书签名认证失败(原因：匹配成功，证书已过期)！";
                     }else  if(subscriberVO.getStatus().equals("2")){
                    	 return "数字证书签名认证失败(原因：匹配成功，证书已吊销)！";
                     } else  if(subscriberVO.getStatus().equals("3")){
                         return "数字证书签名认证失败(原因：用户信息不匹配)！";
                     }  else  if(subscriberVO.getStatus().equals("9")){
                         return "数字证书签名认证失败(原因：证书未知)！";
                     }else {
                         return "数字证书签名认证失败！";
                     }
                }
            }else{
                return "false";
            }
        } catch (ClientException ee) {
            ee.printStackTrace();
            return "error";
        } catch (Exception e){
        	e.printStackTrace();
        	return "error";
        }
    }
    /**
     * 手机验证码校验
     * @param request
     * @param response
     * @param entUser
     * @param model
     * @param tel
     * @param phoneCode
     */
    public String phoneRegister(HttpServletRequest request, HttpServletResponse response,String tel,String phoneCode){
    	//允许在演示或者测试环境下不验证验证码
        String portStr = request.getServerPort()+"";
        String notlogin = codeService.getSysParameter("notlogin");
        if((!Strings.isNullOrEmpty(notlogin))&&(notlogin.equals("Y") && (portStr.equals("9080") || portStr.equals("9081") || portStr.equals("9082") || portStr.equals("9083") || portStr.equals("9088")))
        		|| (!"".equals(portStr)&&notlogin.contains(portStr))){
	            return null;
        }
        String validity = codeService.getSysParameter(SysConstants.VERICODEVALIDITYCONFIG);
        int effecTime = 5;
        if (validity != null && !"".equals(validity)) {
            effecTime = Integer.parseInt(validity);
        }
        String error = "";
        List<DynamicPD> dynPDList = mesgService.findDynamicPDByEnUserTelAndNow(tel, new Date(), effecTime);
        if (dynPDList == null || dynPDList.size() <= 0) {
            LoginLog loginLog = new LoginLog();
            loginLog.setEnUserID(Long.parseLong(tel));
            loginLog.setCreateDate(new Date());
            loginLog.setState(LoginLog.LOGINFAILED);
            mesgService.saveLoginLog(loginLog);
            DynamicPD dPD = mesgService.findDynamicPDByEnUserTelAndPD(tel, phoneCode);
            if (dPD != null && dPD.getId() != null) {
                error = "手机验证码已失效！";
            } else {
                error = "手机验证码错误！";
            }
            return error;
        } else {
            DynamicPD dynamicPD = dynPDList.iterator().next();
            if (!dynamicPD.getDynamicPD().equals(phoneCode)) {
                LoginLog loginLog = new LoginLog();
                loginLog.setEnUserID(Long.parseLong(tel));
                loginLog.setCreateDate(new Date());
                loginLog.setState(LoginLog.LOGINFAILED);
                mesgService.saveLoginLog(loginLog);
                error = "手机验证码错误！";
                return error;
            } else {
                LoginLog loginLog = new LoginLog();
                loginLog.setEnUserID(Long.parseLong(tel));
                loginLog.setCreateDate(new Date());
                loginLog.setState(LoginLog.LOGINSUCCEED);
                mesgService.saveLoginLog(loginLog);
            }
        }
        return null;
    }

    /**
     * 陈迪 添加iframe 子页面超时处理action
     * @param request
     * @param response
     * @param model
     * @return
     */
    @RequestMapping("/timeOut.action")
    public String timeOut(HttpServletRequest request, HttpServletResponse response, ModelMap model){
        LoginException ex = new LoginException("您还没有登录或登录超时，请重新登录！");
        request.setAttribute("base", request.getContextPath());
        request.setAttribute("cssChoicesFlag", codeService.getSysParameter(SysConstants.CSSCHOICESFLAG));
        request.setAttribute("interfaceKindFlag", codeService.getSysParameter(SysConstants.interfaceKindFlag));
        request.setAttribute("tags", codeService.getTagTipsCode());
        request.setAttribute("uniScIDSign", codeService.getSysParameterAsBoolean(SysConstants.uniScIDSign));
        //request.setAttribute("disHeader", codeService.getSysParameterAsBoolean(SysConstants.disHeader));
        request.setAttribute("validateSign",codeService.getSysParameter(SysConstants.validateSign));
        request.setAttribute("phoneLogin",codeService.getSysParameterAsBoolean(SysConstants.phoneLogin));
        request.setAttribute("CALogin",codeService.getSysParameterAsBoolean(SysConstants.CALogin));
        request.setAttribute("yyzzLogin",codeService.getSysParameterAsBoolean(SysConstants.yyzzLogin));
        request.setAttribute("xinAnCa", codeService.getSysParameterAsBoolean(SysConstants.xinAnCa));
        request.setAttribute("ex", ex);
        return "/template/error/loginTimeout.html";
    }
    private boolean compareTime(Date timestamp,Date now,int amount){
    	if(timestamp==null||now==null){
    		return true;
    	}
    	Calendar calendar = new GregorianCalendar();
        calendar.setTime(now);
        calendar.add(Calendar.MINUTE, -amount);
        Date amountMinAfter = calendar.getTime();
        return timestamp.getTime() > amountMinAfter.getTime();
    }
    /**
     * 
     * @Title:        title
     * @Description:  生成实名认证扫码图片
     * @param request
     * @param response
     * @param model
     * @throws Exception    
     * @version       V2.1
     * @author        wuwanran
     * @Date          2017年10月12日 上午10:02:53
     */
    @RequestMapping("/realNameQRImg.action")
	public void realNameQRImg(HttpServletRequest request,HttpServletResponse response, ModelMap model) throws Exception {
    	String paperNumber = request.getParameter("paperNumber");
    	String phone = request.getParameter("phone");
    	String name = request.getParameter("name");
    	String area=PropertiesUtil.getValueByKey ("AreaCodePT");
		if(StringUtils.isNotEmpty(name)){
    		name = URLDecoder.decode(name,"UTF-8").trim();
    	}else{
    		name="";
    	}
		String param="paperNumber="+paperNumber+"&name="+name+"&phone="+phone+"&flag=gajgrz"+"&area="+area;
		response.setHeader("Content-Disposition", "attachment; filename=" + java.net.URLEncoder.encode("ewm", "UTF-8"));
		response.setContentType("application/octet-stream; charset=utf-8");
		ServletOutputStream os = response.getOutputStream();
		InputStream in = QRCodeGenerate.encode(param, 200, 200, 0);
		byte b[] = new byte[1024];
		for (int j = 0; (j = in.read(b)) >= 0;) {
			os.write(b, 0, j);
		}
		in.close();
		os.close();
	}
    @RequestMapping("/realNameSM.action")
    public String realNameSM(HttpServletRequest request,HttpServletResponse response,ModelMap model) throws Exception{
    	String paperNumber = request.getParameter("paperNumber");
    	String phone = request.getParameter("phone");
    	String name = request.getParameter("name");
    	
    	String param = "paperNumber="+paperNumber+"&name="+name+"&phone="+phone;
    	model.put("param", param);
    	return "template/registerRealName/realNameSM.html";
    }
    @RequestMapping("/realNameInfoCheck.action")
    @ResponseBody
    public Map<String,Object> realNameInfoCheck(HttpServletRequest request, HttpServletResponse response, ModelMap model) throws IOException{
    	Map<String,Object> map = new HashMap<String,Object>();
    	String name = request.getParameter("name");
    	if(StringUtils.isNotEmpty(name)){
    		name = URLDecoder.decode(name,"UTF-8").trim();
    	}else{
    		name="";
    	}
    	String paperNumber = request.getParameter("paperNumber");
    	if(paperNumber!=null&&!"".equals(paperNumber)){
    		paperNumber=URLDecoder.decode(paperNumber,"UTF-8").trim();
    	}else if(paperNumber==null){
    		paperNumber = "";
    	}
    	Certification certification = busService.getByPaperNum(paperNumber);
    	if(certification!=null){
    		map.put("realName", true);
    		if(!StringUtils.equals(name, certification.getName())){
    			map.put("realNameError", true);
    		}
    	}else{
    		map.put("realName", false);
    	}
    	return map;
    }
    @RequestMapping("/wuhanLogin1.action")
    public String wuhanLogin1(HttpServletRequest request, HttpServletResponse response, HttpSession session,
                      ModelMap model) throws IOException{
    	//plain=IdNo|420984198510180031~MobilePhone|15927397345~Name|周鹏~Time|20160101111111
    	boolean phoneLoginFlag=codeService.getSysParameterAsBoolean(SysConstants.PHONELOGINFLAG);
    	String plain = request.getParameter("plain");
    	String entType = request.getParameter("entType");
    	String busType = request.getParameter("busType");
    	String sign=request.getParameter("sign");
    	String cerno ="";
    	String name ="";
    	String mobile="";
    	//使用汉口银行的校验方法，
    	//Map checkSign(String plain,String sign ,boolean mod,Long timOut),plain:签名原文;sign:签名密文;mod:模式(true-生产   false-测试);timOut:超时时间	(单位：毫秒)
    	Map checkSign = new CheckSignData().checkSign(plain, sign, true, 60*60*1000L);//暂定超时时间为60分钟
    	String resultSign="";
    	if(checkSign!=null){
    		String returnCode=(String) checkSign.get("ReturnCode");
    		if(returnCode!=null && "000000".equals(returnCode)){//验签成功
    			cerno=(String) checkSign.get("IdNo");
    			mobile=(String) checkSign.get("MobilePhone");
    			name=(String) checkSign.get("Name");
    			resultSign="000000";
    		}else{
    			resultSign=(String)checkSign.get("ReturnMsg");
    		}
    	}else{
    		resultSign="验签失败";
    	}
    	if(!"000000".equals(resultSign)){
    		throw new RuntimeException(resultSign);
    	}
    	EntUser user = entUserService.findByUsername(cerno,phoneLoginFlag);
		if(user==null || user.getId()==null){
			user=new EntUser();
			user.setUserType("5");
			user.setUsername(cerno);
			user.setPassword(MD5Util.createEncryptPSW(mobile));
			user.setElename(name);
			user.setElepapernumber(cerno);
			user.setTel(mobile);
			entUserService.save(user);
		}else{
			user.setUserType("5");
			user.setUsername(cerno);
			user.setPassword(MD5Util.createEncryptPSW(mobile));
			user.setElename(name);
			user.setElepapernumber(cerno);
			user.setTel(mobile);
			entUserService.update(user);
		}
		session.setAttribute("entUser", user);
        
    	if (codeService.getSysParameterAsBoolean(SysConstants.UserHandleEntForManyFlag)) {
    		if(codeService.getSysParameterAsBoolean(SysConstants.USERCENTER)){
				return "redirect:/toUserCenter.action";//用户中心
	    	}else{
	            if("01".equals(busType) || busType==null || "".equals(busType)){
	            	if(entType!=null && !"".equals(entType)){
	            		return "redirect:/namereg/pre.action?entTypeChose="+entType;//业务引导
	            	}
	            	return "redirect:/guide.action?busiType=01";//业务引导
	            }else{
	            	return "redirect:/guide.action?busiType=02";//业务引导
	            }
	    	}
        }else{
        	List<BusiMainBodyInfo> list = busiMainBodyInfoService.findBusiMainBodyInfoByUserId(user.getId());
        	if(list!=null && list.size()>0){
        		BusiMainBodyInfo item = list.get(0);
        		if(BusiMainBodyInfo.BUSITYPE_SL.equals(item.getBusiType())){
        			return "redirect:/register/mainBodyUI.action?busiId="+item.getId();
        		}else if(BusiMainBodyInfo.BUSITYPE_MC.equals(item.getBusiType())){
        			return "redirect:/namereg/flowChoices.action?busiId="+item.getId();
        		}
        	}
        	if("01".equals(busType) || busType==null || "".equals(busType)){
        		if(entType!=null && !"".equals(entType)){
            		return "redirect:/namereg/pre.action?entTypeChose="+entType;//业务引导
            	}
            	return "redirect:/guide.action?busiType=01";//业务引导
            }else{
            	return "redirect:/guide.action?busiType=02";//业务引导
            }
        }
    }
    
    @RequestMapping("/dzyyzzQRcodeUI.action")
    public String uploadQRcodeUI(HttpServletRequest request, HttpServletResponse response, ModelMap model){
        
        return "/template/dzyyzzQRcode.html";
    }
    /**
     * 生成电子营业执照二维码
     * @param request
     * @param response
     * @throws Exception
     */
    @RequestMapping("/showDzyyzzEwm.action")
    public void showEwm(HttpServletRequest request, HttpServletResponse response) throws Exception{
        String dzyyzzAppQRDownloadUrl = codeService.getSysParameter(SysConstants.dzyyzzAppQRDownloadUrl);
       /* String ewmAddress = "http://"+request.getServerName()+":"+request.getServerPort()+""+request.getContextPath();//当前项目地址
        String dzyyzzActionUrl = "/index.action";//电子营业执照APP的路径
        StringBuffer  content=new StringBuffer();
        content.append(ewmAddress);
        content.append(dzyyzzActionUrl);
        String contents=content.toString();*/
        response.setHeader("Content-Disposition", "attachment; filename=" + java.net.URLEncoder.encode("ewm", "UTF-8"));
        response.setContentType("application/octet-stream; charset=utf-8");
        ServletOutputStream os = response.getOutputStream();
        InputStream in = QRCodeGenerate.encode(dzyyzzAppQRDownloadUrl, 150, 150, 0);
        byte abyte0[] = new byte[1024];
        for (int j = 0; (j = in.read(abyte0)) >= 0;) {
            os.write(abyte0, 0, j);
        }
        in.close();
        os.close();
    }
    /**
     * 
     * @Title:        title
     * @Description:  西藏公安实名认证
     * @param request
     * @param paperNumber
     * @param name
     * @return    
     * @author        wuwanran
     * @Date          2018年1月15日 上午10:00:36
     */
    public String realNamePolic_xz(HttpServletRequest request,String paperNumber,String name){
    	String senderId = codeService.getSysParameter(SysConstants.xz_senderId);//"C 20-1000000008";//请求方ID
    	String serviceId = codeService.getSysParameter(SysConstants.xz_serviceId);//"S10-1000000001";//服务方ID
    	String authorizeInfo = codeService.getSysParameter(SysConstants.xz_authorizeInfo);//"88A OC R1kBr3P";//授权信息
    	String method ="Query";//请求的接口方法
    	String userDept = codeService.getSysParameter(SysConstants.xz_userDept);//"540000";//行政区划
    	String ip = request.getServerName();
    	JSONObject endUser = new JSONObject();//请求的接口方法的参数 endUser
	    	endUser.element("UserCardId", paperNumber);
	    	endUser.element("UserName", name);
	    	endUser.element("UserDept", userDept);
    	
	    	JSONObject params = new JSONObject();//请求的接口方法的参数
	    	params.element("EndUser", endUser);
	    	params.element("Method", method);
	    	params.element("Condition", "SFZH='"+paperNumber+"'");
	    	params.element("OrderItems", "");
	    	params.element("RequiredItems", "SFZH");
	    	params.element("RowsPerPage", "10");
	    	params.element("PageNum", "1");
	    	params.element("InfoCodeMode", "0");
    	JSONObject operate = new JSONObject();//操作信息
    		operate.element("userId", paperNumber);
    		operate.element("userName", name);
    		operate.element("userDept", userDept);
    		operate.element("macIp", ip);
    	
    	JSONObject json = new JSONObject();//请求参数
	    	json.element("senderId", senderId);
	    	json.element("serviceId", serviceId);
	    	json.element("authorizeInfo", authorizeInfo);
	    	json.element("method", method);
	    	json.element("params", params);
	    	json.element("operate", operate);
    	 CloseableHttpClient httpclient = HttpClientBuilder.create().build();
    	 String url = codeService.getSysParameter(SysConstants.xz_policUrl);
         HttpPost post = new HttpPost(url);
         String str = "";
         try{
        	 System.out.println("西藏公安厅接口请求信息+"+json.toString());
	         StringEntity s = new StringEntity(json.toString());
	         s.setContentEncoding("UTF-8");
	         s.setContentType("application/json");//发送json数据需要设置contentType
	         post.setEntity(s);
	         HttpResponse res = httpclient.execute(post);
	         if(res.getStatusLine().getStatusCode() == HttpStatus.SC_OK){
	        	 str = EntityUtils.toString(res.getEntity());// 返回json格式：
	        	 System.out.println("西藏公安接口返回信息============="+str);
	         }
         }catch(Exception e){
        	 e.printStackTrace();
        	 throw new RuntimeException("----西藏公安接口调用失败----");
         }
         JSONObject strJson = JSONObject.fromObject(str);
         String payLoad = strJson.getString("payLoad");
         JSONObject res = JSONObject.fromObject(payLoad);
         String code = res.getString("Code");
         if("000".equals(code)){
        	 return"";
         }else{
        	 return res.getString("Message");
         }
    }
    /**
     * 处理企业用户的用户与企业信息关联数据
     * @param nmb
     * @param lepAndMarInfo
     * @param user
     * @return
     * @author ruanyongcan 2018-01-19
     */
    public LepAndMarInfoOfUser dealLepAndMarInfoData(NetMainBody nmb,LepAndMarInfoOfUser lepAndMarInfo,EntUser user){
    	if (nmb.getUniScID()!=null && !"".equals(nmb.getUniScID())) {
    		lepAndMarInfo.setUniscId(nmb.getUniScID());
    	} else {
    		lepAndMarInfo.setUniscId(nmb.getCertificateNo());
    	}
    	lepAndMarInfo.setMarprId(nmb.getId());
    	lepAndMarInfo.setChoseSign("Y");
    	lepAndMarInfo.setUserType(LepAndMarInfoOfUser.USERTYPE_3);
    	lepAndMarInfo.setUserId(user.getId());
    	lepAndMarInfo.setEntName(nmb.getName());
    	lepAndMarInfo.setCreateTime(new Date());
    	lepAndMarInfo = getUserType(nmb,lepAndMarInfo,user);
    	lepAndMarInfo.setUserLevel(getUserLevel(nmb,lepAndMarInfo,user));
    	return lepAndMarInfo;
    }
    /**
     * 获取用户权限等级
     * @param netMainBody
     * @param lepAndMarInfo
     * @return
     */
    public String getUserLevel(NetMainBody netMainBody,LepAndMarInfoOfUser lepAndMarInfo,EntUser entUser){
    	String elepapernumber= entUser.getElepapernumber();
    	String elepaper = entUser.getElepaper();
//    	String userLevel = LepAndMarInfoOfUser.USERLEVEL_4;
    	if(lepAndMarInfo.getCerNo().equals(elepapernumber) && lepAndMarInfo.getCerType().equals(elepaper)) {
    		return LepAndMarInfoOfUser.USERLEVEL_1;//用户证件号码是法定代表人号码的
    	} else {
    		//判断用户证件号码是股东号码
    		List<NetInvestor> netInvestorList = busService.findNetInvestorByMainBodyId(netMainBody.getId());
    		if (netInvestorList!=null && netInvestorList.size()>0) {
    			for (NetInvestor netInvestor:netInvestorList) {
    				if (netInvestor.getCertificateNo()!=null && netInvestor.getCertificateNo().equals(elepapernumber)
    						&& netInvestor.getCardType()!=null && netInvestor.getCardType().equals(elepaper)) {
    					return LepAndMarInfoOfUser.USERLEVEL_2;//用户证件号码是股东证件号码
    				}
    			}
    		}
    		//判断用户证件号码是管理人号码
    		List<NetPostProve> netPostProveList = busService.findNetPostProveByMainbodyId(netMainBody.getId());
    		if (netPostProveList!=null && netPostProveList.size()>0) {
    			for (NetPostProve netPostProve:netPostProveList) {
    				if (netPostProve.getCertifNo()!=null && netPostProve.getCertifNo().equals(elepapernumber)
    						&& netPostProve.getCardType()!=null && netPostProve.getCardType().equals(elepaper)) {
    					return LepAndMarInfoOfUser.USERLEVEL_3;//用户证件号码是管理人员证件号码
    				}
    			}
    		}
    		return LepAndMarInfoOfUser.USERLEVEL_4;
    	}
    }
    /**
     * 给PUB_LEPANDMARINFOOFUSER表写入法定代表人信息
     * @param netMainBody
     * @param lepAndMarInfo
     * @param entUser
     * @return
     */
	 public LepAndMarInfoOfUser getUserType(NetMainBody netMainBody,LepAndMarInfoOfUser lepAndMarInfo,EntUser entUser){
    	if(netMainBody.getState().equals(NetMainBody.MAINBODY_STATE_NORMAL)){
			//不管所有企业类型都先查法人表
			NetLegalPerson netLegalPerson=busService.findNetLegalPersonByMarprid(netMainBody.getId());
			if(netLegalPerson!=null && netLegalPerson.getId()!=null){
				lepAndMarInfo.setName(netLegalPerson.getName());
				lepAndMarInfo.setCerType(netLegalPerson.getCertificateType());
				lepAndMarInfo.setCerNo(netLegalPerson.getCertificateCode());
			}
			//如果没有法人信息，则查执行事务合伙人表
			if(netLegalPerson==null){
				List<ExecutivePartner> executivePartner=busService.findExecutivePartnersByMarprid(netMainBody.getId());
				if(executivePartner!=null && executivePartner.size()>0){
					for(ExecutivePartner e:executivePartner){
						if (e.getId()!=null){
							lepAndMarInfo.setName(e.getName());
							lepAndMarInfo.setCerType(e.getCertificateType());
							lepAndMarInfo.setCerNo(e.getCertificateCode());
							break;
						}
					}
				}
			}
    	}
		return lepAndMarInfo;
    }
	 /**
	  * 
	 	* @Description: 获取服务器当前日期的毫秒数
	 	* @param @param request
	 	* @param @param response
	 	* @param @return
	 	* @param @throws IOException   
	 	* @return String  
	 	* @throws
	 	* @author dongxianli
	 	* @date 2018年2月5日
	  
	  */
	 @RequestMapping({"/getServiceTime.action"})
	 @ResponseBody
	 public String getServiceTime(HttpServletRequest request, HttpServletResponse response) throws IOException{
		 Calendar c = Calendar.getInstance();
		 c.setTime(new Date());
		 c.set(Calendar.HOUR_OF_DAY, 0);
		 c.set(Calendar.MINUTE, 0);
		 c.set(Calendar.SECOND, 0);
		 c.set(Calendar.MILLISECOND, 0);
		 String time = c.getTimeInMillis() + "";
		 return time;
	 }

    /**
     *
     * @Description: 调用生成芝麻认证二维码
     * @author yangzongxin
     * @date 2018年4月4日
     */
    @RequestMapping("/realZhimaSM.action")
    public String realZhimaSM(HttpServletRequest request,HttpServletResponse response,ModelMap model) throws UnsupportedEncodingException {
        String gateway_url = codeService.getSysParameter(SysConstants.gateway_url);
        String app_id = codeService.getSysParameter(SysConstants.app_id);
        String merchant_private_key = codeService.getSysParameter(SysConstants.merchant_private_key);
        String alipay_public_key = codeService.getSysParameter(SysConstants.alipay_public_key);
        String zmrz_return_url = codeService.getSysParameter(SysConstants.zmrz_return_url);
        String phone = request.getParameter("phone");
        AlipayClient alipayClient = new DefaultAlipayClient(gateway_url, app_id, merchant_private_key, "json", "utf-8", alipay_public_key, "RSA2");
        ZhimaCustomerCertificationInitializeRequest req = new ZhimaCustomerCertificationInitializeRequest();
        ZhimaCustomerCertificationInitializeModel mod = new ZhimaCustomerCertificationInitializeModel();
        //商户请求的唯一标志
        String transactionId = this.getAlipayMerchantCode();
        mod.setTransactionId(transactionId);
        //芝麻认证产品码
        mod.setProductCode("w1010100000000002978");
        //认证场景码,FACE：多因子活体人脸认证， CERT_PHOTO_FACE 签约的协议决定了可以使用的场景
        mod.setBizCode("CERT_PHOTO_FACE");
        req.setBizModel(mod);
        try {
            ZhimaCustomerCertificationInitializeResponse res = alipayClient.execute(req);
            System.out.println(res.getBody());
            System.out.println("bizNo:" + res.getBizNo());
            if(res.isSuccess()){
                System.out.println("芝麻认证初始化调用成功");
                ZhimaCustomerCertificationCertifyRequest reqSm = new ZhimaCustomerCertificationCertifyRequest();
                ZhimaCustomerCertificationCertifyModel modSm = new ZhimaCustomerCertificationCertifyModel();
                modSm.setBizNo(res.getBizNo());
                reqSm.setBizModel(modSm);
                // 设置回调地址
                zmrz_return_url = zmrz_return_url + "?phone=" + phone + "&";
                reqSm.setReturnUrl(zmrz_return_url);
                System.out.println("芝麻认证回调路径-------"+zmrz_return_url);
                try {
                    ZhimaCustomerCertificationCertifyResponse responseFh = alipayClient.pageExecute(reqSm, "GET");
                    System.out.println(responseFh.getBody());
                    if(responseFh.isSuccess()){
                        String generateCertifyUrl = responseFh.getBody().substring(0, responseFh.getBody().lastIndexOf("&sign"));
                        System.out.println("generateCertifyUrl url:" + generateCertifyUrl);
                        model.put("param", generateCertifyUrl);
                        model.put("bizNo", res.getBizNo());
                        System.out.println("生成二维码成功！");
                    } else {
                        System.out.println("生成二维码失败！");
                    }
                    return "template/registerRealName/realZhimaSM.html";
                } catch (AlipayApiException e) {
                    e.printStackTrace();
                    throw new RuntimeException("芝麻认证二维码地址生成失败！");
                }
            } else {
                throw new RuntimeException("认证信息有误请重新填写！");
            }
        } catch (AlipayApiException e) {
            e.printStackTrace();
            throw new RuntimeException("认证信息有误请重新填写！");
        }
    }

    /**
     *
     * @Description: 芝麻认证回调：实名认证信息保存
     * @author yangzongxin
     * @date 2018年4月4日
     */
    @RequestMapping("/saveZhimaRealName.action")
    private String saveZhimaRealName(HttpServletRequest request,HttpServletResponse response, HashMap<String, Object> map) throws UnsupportedEncodingException {
        String gateway_url= codeService.getSysParameter(SysConstants.gateway_url);
        String app_id= codeService.getSysParameter(SysConstants.app_id);
        String merchant_private_key= codeService.getSysParameter(SysConstants.merchant_private_key);
        String alipay_public_key= codeService.getSysParameter(SysConstants.alipay_public_key);
        //从回调URL中获取params参数，此处为示例值
        String params = request.getParameter("biz_content");
        String phone = request.getParameter("phone");
        params = StringEscapeUtils.unescapeHtml4(params);
        JSONObject  paramsJson = JSONObject.fromObject(params);
        String bizNo = paramsJson.getString("biz_no");
        if(bizNo.indexOf("%") != -1) {
            bizNo = URLDecoder.decode(bizNo, "UTF-8");
        }
        if(phone.indexOf("%") != -1) {
            phone = URLDecoder.decode(phone, "UTF-8");
        }
        AlipayClient alipayClient = new DefaultAlipayClient(gateway_url,app_id,merchant_private_key,"json","utf-8",alipay_public_key,"RSA2");
        ZhimaCustomerCertificationQueryRequest req = new ZhimaCustomerCertificationQueryRequest();
        JSONObject bizContent = new JSONObject();
        bizContent.put("biz_no", bizNo);
        req.setBizContent(bizContent.toString());
        try {
            ZhimaCustomerCertificationQueryResponse resFh = alipayClient.execute(req);
            System.out.println(resFh.getBody());
            if (resFh.isSuccess() && "true".equals(resFh.getPassed())) {
                System.out.println("回调验证成功！");
                JSONObject  resJson = JSONObject.fromObject(resFh.getBody());
                String zhimaResponse = resJson.getString("zhima_customer_certification_query_response");
                System.out.println(zhimaResponse);
                JSONObject  zhimaQueryJson = JSONObject.fromObject(zhimaResponse);
                String identityInfo = zhimaQueryJson.getString("identity_info");
                JSONObject  identityInfoJson = JSONObject.fromObject(identityInfo);
                //姓名或企业名称
                String name = identityInfoJson.getString("cert_name");
                //证件类型(默认为身份证类型)
                String paper = "10";
                //证件号码
                String paperNumber = identityInfoJson.getString("cert_no");
                //认证方式(定死为4芝麻认证)
                String authType = "4";
                //获取证件照片细信息
                String channelStatuses = zhimaQueryJson.getString("channel_statuses");
                JSONArray channelStatusesJson = JSONArray.fromObject(channelStatuses);
                JSONObject facialJson = channelStatusesJson.getJSONObject(0).getJSONObject("materials");
                //认证拍摄照片
                String facialPictureFront = facialJson.getString("FACIAL_PICTURE_FRONT");
                System.out.println("facialPictureFront----------->"+facialPictureFront);
                JSONObject residentJson = channelStatusesJson.getJSONObject(1).getJSONObject("materials");
                //身份证反面
                String residentEmblem = residentJson.getString("RESIDENT_EMBLEM");
                System.out.println("residentEmblem----------->"+residentEmblem);
                //身份证正面
                String residentIdentity = residentJson.getString("RESIDENT_IDENTITY");
                System.out.println("residentIdentity----------->"+residentIdentity);
                //身份证正面
                String fileFront = residentIdentity;
                //身份证反面
                String fileOpposite = residentEmblem;
                //认证照片
                String fileAuthentication = facialPictureFront;
                if (StringUtils.isNotEmpty(name) && StringUtils.isNotEmpty(paper)
                        && StringUtils.isNotEmpty(paperNumber)
                        && StringUtils.isNotEmpty(authType)
                        && StringUtils.isNotEmpty(phone)) {
                    if (StringUtils.isNotEmpty(fileFront)
                            && StringUtils.isNotEmpty(fileOpposite)
                            && StringUtils.isNotEmpty(fileAuthentication)) {
                        // 保存身份证正反面
                        IdCard idCard = datumService.findIdCardCernos(paperNumber, IdCard.ZJLX_S);
                        if (idCard == null) {
                            idCard = new IdCard();
                        }
                        // 文件size
                        Integer size = 0;
                        BASE64Decoder decoder = new BASE64Decoder();
                        byte[] fileFrontByte = null;
                        byte[] fileOppositeByte = null;
                        byte[] fileAuthenticationByte = null;
                        try {
                            fileFrontByte = decoder.decodeBuffer(fileFront);
                            fileOppositeByte = decoder.decodeBuffer(fileOpposite);
                            fileAuthenticationByte = decoder.decodeBuffer(fileAuthentication);
                        } catch (IOException e) {
                            // TODO Auto-generated catch block
                            e.printStackTrace();
                        }
                        idCard.setContentZm(fileFrontByte);
                        idCard.setContentFm(fileOppositeByte);
                        idCard.setContentSc(fileAuthenticationByte);
                        idCard.setCerno(paperNumber);// 证件号码
                        idCard.setCertype(IdCard.Type_A);// 证件类型
                        idCard.setCreatedate(new Date());
                        idCard.setModifydate(new Date());
                        idCard.setType(IdCard.Type_Z);
                        idCard.setSize(size);
                        idCard.setZzlx(IdCard.ZJLX_S);
                        if (idCard.getId() == null) {
                            idCard.setId(busiMainBodyInfoService.getSeq());
                            // 保存
                            datumService.creatIdCard(idCard);
                        } else {
                            datumService.updateIdCard(idCard);
                        }
                    }
                    // 保存实名认证信息
                    Certification certification = busService.getByPaperNum(paperNumber);
                    if (certification == null) {
                        certification = new Certification();
                    }
                    certification.setName(name);
                    certification.setPaper(paper);
                    certification.setPaperNumber(paperNumber.toUpperCase());
                    certification.setPhone(phone);
                    certification.setAuthType(authType);
                    certification.setAuthFlag("1");

                    if (Strings.isNullOrEmpty(certification.getApplySign())) {
                        certification.setApplySign("0");
                    }
                    if (Strings.isNullOrEmpty(certification.getApplyType())) {
                        certification.setApplyType("1");
                    }
                    Date nowDate = new Date();
                    certification.setTimestamp(nowDate);
                    if (certification.getApplyNum() == 0) {
                        certification.setApplyNum(0);
                    }
                    if (certification.getId() == null) {
                        certification.setCreateDate(nowDate);
                        certification.setId(busiMainBodyInfoService.getSeq());
                        busService.save(certification);
                    } else {
                        busService.update(certification);
                    }
                    setResult(map, true, null);
                } else {
                    setResult(map, false, "参数不完整！");
                }
            } else {
                System.out.println("回调验证失败！");
            }
        } catch (AlipayApiException e) {
            e.printStackTrace();
            throw new RuntimeException("回调验证失败！");
        }
        return "template/registerRealName/realZhimaFH.html";
    }

    private void setResult(HashMap<String, Object> map, boolean result, String msg) {
        map.put("success", result);
        if (msg != null && !msg.isEmpty()){
            map.put("msg", msg);
        }
    }

    /**
     *
     * @Description: 生成商户请求的唯一标志，32位长度的字母数字下划线组合。该标识作为对账的关键信息，商户要保证其唯一性.
     * 建议:前面几位字符是商户自定义的简称,中间可以使用一段日期,结尾可以使用一个序列
     * @author yangzongxin
     * @date 2018年4月4日
     */
    private String getAlipayMerchantCode() {
        //商户自定义的简称:工商认证首字母大写
        long time = System.currentTimeMillis();
        String code="GSRZ" + new SimpleDateFormat("yyyyMMddHHmmss").format(time) +"0001234";
        return code;
    }

    /**
     *
     * @Description: 调用生成芝麻认证二维码
     * @author yangzongxin
     * @date 2018年4月4日
     */
    @RequestMapping("/getAuthenticationInfoByBizNo.action")
    @ResponseBody
    public Map<String, Object> getAuthenticationInfoByBizNo(HttpServletRequest request,HttpServletResponse response,ModelMap model) throws Exception {
        Map<String,Object> map = new HashMap<String, Object>();
        String gateway_url = codeService.getSysParameter(SysConstants.gateway_url);
        String app_id = codeService.getSysParameter(SysConstants.app_id);
        String merchant_private_key = codeService.getSysParameter(SysConstants.merchant_private_key);
        String alipay_public_key = codeService.getSysParameter(SysConstants.alipay_public_key);
        String zmrz_return_url = codeService.getSysParameter(SysConstants.zmrz_return_url);
        String bizNo = request.getParameter("bizNo");
        AlipayClient alipayClient = new DefaultAlipayClient(gateway_url,app_id,merchant_private_key,"json","utf-8",alipay_public_key,"RSA2");
        ZhimaCustomerCertificationQueryRequest req = new ZhimaCustomerCertificationQueryRequest();
        JSONObject bizContent = new JSONObject();
        bizContent.put("biz_no", bizNo);
        req.setBizContent(bizContent.toString());
        try {
            ZhimaCustomerCertificationQueryResponse resFh = alipayClient.execute(req);
            System.out.println(resFh.getBody());
            if (resFh.isSuccess() && "true".equals(resFh.getPassed())) {
                JSONObject  resJson = JSONObject.fromObject(resFh.getBody());
                String zhimaResponse = resJson.getString("zhima_customer_certification_query_response");
                System.out.println(zhimaResponse);
                JSONObject  zhimaQueryJson = JSONObject.fromObject(zhimaResponse);
                String identityInfo = zhimaQueryJson.getString("identity_info");
                JSONObject  identityInfoJson = JSONObject.fromObject(identityInfo);
                //姓名或企业名称
                String name = identityInfoJson.getString("cert_name");
                //证件号码
                String paperNumber = identityInfoJson.getString("cert_no");
                map.put("success", true);
                map.put("name", name);
                map.put("paperNumber", paperNumber);
                return map;
            } else {
                map.put("success", false);
                map.put("msg", "认证失败！");
                return map;
            }
        } catch (AlipayApiException e) {
            e.printStackTrace();
            throw new RuntimeException("认证失败！");
        }
    }

}
