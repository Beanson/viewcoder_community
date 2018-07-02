
import org.apache.commons.codec.binary.Hex;
import org.apache.log4j.Logger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Created by Administrator on 2018/7/2.
 * 在GitHub中公开进行认证的代码块
 */
public class Verification {

    private static final String PUBLIC_KEY_STR = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEql8tKMHvu/Mt7+ftWS8BUdRrFx1mXU+3996R66eHUe4v8PaHTri8ZvDT6VswMmWYAfSLLbvy9cN0vQtBnPk59A==";
    private static Logger logger = Logger.getLogger(Verification.class);

    //Base64编码转字节数组
    private static byte[] base642Byte(String base64Key) {
        Base64.Decoder decoder = Base64.getDecoder();
        return decoder.decode(base64Key);
    }

    public static void main(String[] args) throws Exception {

        try {
            //1. 基础环境配置
            //   a. java开发环境
            //   b. 如果使用jdk9以上则忽略该步骤，否则需拓展jdk的security包：
            //      根据jdk版本搜索并下载对应版本的Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files 8/7/6/...
            //      以jdk8为例进入http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html 下载jce_policy-8.zip
            //   c  local_policy.jar 和 US_export_policy.jar替换掉jdk和jre中 \lib\security下面的相同的两个jar包
            //   d. 下载bouncycastle的jar文件，加入classpath中或作为项目引用包。地址：http://mvnrepository.com/artifact/org.bouncycastle/bcprov-jdk15on

            //2. 分别填充数字签名摘要和原文到contentStr和signatureStr字段
            //如{"sign":"123","content":"abc"}，则signatureStr="123", contentStr="abc"
            String signatureStr = "place the signature here";
            String contentStr = "place the content here";
            
            //3.验证签名
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(base642Byte(PUBLIC_KEY_STR));
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
            Signature signature = Signature.getInstance("SHA256withECDSA");
            signature.initVerify(publicKey);
            signature.update(contentStr.getBytes());
            boolean bool = signature.verify(Hex.decodeHex(signatureStr.toCharArray()));
            logger.debug("Trade signature verify result: " + bool);

        } catch (Exception e) {
            logger.error("Trade signature verify occurs error", e);
        }
    }
}
