# ApplePay
需要檔案:</br>
1. [https://www.apple.com/certificateauthority/AppleRootCA-G3.cer](https://www.apple.com/certificateauthority/AppleRootCA-G3.cer)</br>
2. your Apple Pay Merchant Identity certificate </br>
3. your Apple Pay Payment Processing certificate </br>
---
參考文件:
Apple Pay前置步驟(廠商id與payment憑證申請、JS語法、mac設備設定)請看第1&2份文件
1. ecpay_APPLEPAY.pdf
2. PayNow ApplePay.pdf
---
reference:<br>
	官方文件:<br>
	[Apple Developer Documentation](https://developer.apple.com/documentation/passkit/apple_pay/payment_token_format_reference)<br>
	[Payment Token Format Reference | Apple Developer Documentation](https://developer.apple.com/documentation/passkit/apple_pay/payment_token_format_reference#//apple_ref/doc/uid/TP40014929)<br><br>
	網友分享:<br>
	[輕鬆解密Apple pay payment token. (跳過第三方金融服務商串接Apple Pay)<br> | by Ken Chen | Medium](https://medium.com/@kenchen_57904/%E8%BC%95%E9%AC%86%E8%A7%A3%E5%AF%86apple-pay-payment-token-6e7b900e8e0c)<br>
	[Apple Pay on the Web 開發筆記 | SoarLin](https://soarlin.github.io/2018/03/10/apple-pay-on-the-web-%E9%96%8B%E7%99%BC%E7%AD%86%E8%A8%98/#Apple-Pay-Payment-Request)<br>
	[java后端处理Apple Pay流程 - CodeAntenna](https://codeantenna.com/a/gKpDwWNEwq)<br>
	<br>
	[applepay - Apple Pay Payment Token Decryption in Java - Stack Overflow](https://stackoverflow.com/questions/58020641/apple-pay-payment-token-decryption-in-java)<br>
	[encryption - Apple Pay - How to compare merchant public key with publicKeyHash from payment token? - Stack Overflow](https://stackoverflow.com/questions/45040171/apple-pay-how-to-compare-merchant-public-key-with-publickeyhash-from-payment-t)<br>
	[Payment Token Format Reference | Apple Developer Documentation](https://developer.apple.com/documentation/passkit/apple_pay/payment_token_format_reference#//apple_ref/doc/uid/TP40014929-CH8-SW1)<br>
	<br>
	[applepay-token/README.md at master · sidimansourjs/applepay-token · GitHub](https://github.com/sidimansourjs/applepay-token/blob/master/README.md)<br>
	[applepay-rsa-crypto-demo/ApplePayCryptoUtil.java at master · kula99/applepay-rsa-crypto-demo · GitHub](https://github.com/kula99/applepay-rsa-crypto-demo/blob/master/src/main/java/com/xavier/work/applepay/crypto/ApplePayCryptoUtil.java)<br>
	[ApplePayAndroidPayDecryption/Decryption at master · chengbo/ApplePayAndroidPayDecryption · GitHub](https://github.com/chengbo/ApplePayAndroidPayDecryption/tree/master/Decryption)<br>
	[heartland-java/DecryptService.java at 155bfd39ca011be042e56b8a8ff94ce67282b263 · hps/heartland-java · GitHub](https://github.com/hps/heartland-java/blob/155bfd39ca011be042e56b8a8ff94ce67282b263/src/com/hps/integrator/applepay/ecv1/DecryptService.java#L153)<br>
	[Apple-Pay-Signature-Verification/src/main/java/com/zooz/applepay/signatureverification at master · Zooz/Apple-Pay-Signature-Verification · GitHub](https://github.com/Zooz/Apple-Pay-Signature-Verification/tree/master/src/main/java/com/zooz/applepay/signatureverification)<br>
	[apple-pay-decrypt/index.js at 5f2557bb0ea0afc0ecf43ce961047490979a0e3c · samcorcos/apple-pay-decrypt · GitHub](https://github.com/samcorcos/apple-pay-decrypt/blob/5f2557bb0ea0afc0ecf43ce961047490979a0e3c/index.js#L41)<br>
	[GitHub - chengbo/ApplePayAndroidPayDecryption: A C# library to decrypt Apple Pay or Android Pay token on the server side.](https://github.com/chengbo/ApplePayAndroidPayDecryption)<br>
	[GitHub - psraju1/CSharpApplePayDecrypter: C# Applepay ECDSA decrypter](https://github.com/psraju1/CSharpApplePayDecrypter)<br>
	[GitHub - psraju1/CSharpApplePayDecrypter at dafde5e2daf1f93cd161be3013acef1d65c01239](https://github.com/psraju1/CSharpApplePayDecrypter/tree/dafde5e2daf1f93cd161be3013acef1d65c01239)<br>
	[GitHub - samcorcos/apple-pay-decrypt: Allow user to decrypt Apple Pay token for use with payment processor (Stripe, Braintree, et al)<br>.](https://github.com/samcorcos/apple-pay-decrypt)<br>
	<br>
	[Use the merchant private key and the ephemeral public key, to generate the shared secret using Elliptic Curve Diffie-Hellman (id-ecDH 1.3.132.1.12)<br>. - Google 搜尋](https://www.google.com/search?q=Use+the+merchant+private+key+and+the+ephemeral+public+key%2C+to+generate+the+shared+secret+using+Elliptic+Curve+Diffie-Hellman+(id-ecDH+1.3.132.1.12)<br>.&oq=Use+the+merchant+private+key+and+the+ephemeral+public+key%2C+to+generate+the+shared+secret+using+Elliptic+Curve+Diffie-Hellman+(id-ecDH+1.3.132.1.12)<br>.&aqs=edge..69i57&sourceid=chrome&ie=UTF-8)<br>
	
解密算法:<br>
		橢圓<br>
		[Ephemeral elliptic curve Diffie-Hellman key agreement in Java – Neil Madden](https://neilmadden.blog/2016/05/20/ephemeral-elliptic-curve-diffie-hellman-key-agreement-in-java/)<br>
		[ECDSA & ECDH - 密碼學筆記 (gitbook.io)](https://easonwang.gitbook.io/crypto/ecdsa)<br>
		[SafeCurves: Base points (yp.to)](https://safecurves.cr.yp.to/base.html)<br>
		RSA<br>
		[Java RSA加密解密_梦想成真那天的博客-CSDN博客](https://blog.csdn.net/u012164361/article/details/69945277)<br>
		[Java使用RSA的公钥加密，私钥解密；私钥加密，公钥解密_silangfeilang的博客-CSDN博客_java使用rsa公钥私钥加密解密](https://blog.csdn.net/silangfeilang/article/details/108403723)<br>
		<br>
		[[筆記]Symmetric Encryption 對稱式加密 @ David Liao's Blog :: 痞客邦 :: (pixnet.net)](https://david50.pixnet.net/blog/post/28795947)<br>
		[Java加密与解密笔记(三) 非对称加密 - at0x7c00 - 博客园 (cnblogs.com)](https://www.cnblogs.com/at0x7c00/p/7688124.html)<br>
	憑證:<br>
	[OpenSSL 轉換 PEM、DER、PKCS#12 憑證格式教學與範例 - Office 指南 (officeguide.cc)](https://officeguide.cc/openssl-convert-pem-der-pkcs12-ssl-certificate-tutorial-examples/)<br>
	[OpenSSL& public key and private key & Certificate | by 莊子弘 | Medium](https://ji3g4zo6qi6.medium.com/openssl-public-key-and-private-key-certificate-28b990457496)<br>
	
工具: <br>
		[Online JSON Viewer (stack.hu)](http://jsonviewer.stack.hu/)<br>



正文開始:
---

流程概述

	此處僅解釋後端解碼流程，前端由safari文件說明(下面還是會講啦)。
		1.MerchantId Validate: use MerchantId-test.p12 
		2.Payment Processing: use ProcessingCert.p12 and AppleRootCA-G3.cer
		├─Step.1 Verify the signature -> SignatureVerifier.validate(applePayData, applePayPaymentHe ader, applePaySignature,APPLE_PAY_SIGNATURE_EXPIRATION_IN_MS);
		│	├step 1: Ensure that the certificates contain the correct custom OIDs	
		│	├step 2: Ensure that the root CA is the Apple Root CA - G3
		│	├step 3: Ensure that there is a valid X.509 chain of trust from the signature to the root CA. Specifically
		│	├step 4: Ensure that the signature is a valid ECDSA signature
		│	└step 5: Inspect the CMS signing time of the signature
		├─Step.2 Determine which merchant public key was use -> PublicKeyHashVerifier.validate(publicKeyHash);
		│	└step 1: checkPublicKeyHash
		├─Step.3 Restore the symmetric key -> RestoreSymmetricKey.decrypt(applePayPaymentHeader);
		│	├step 1: a. Use the merchant private key and the ephemeral public key...
		│	└step 2: b. Use the merchant identifier field (OID 1.2.840.113635.100.6.32) of the public key certificate and the shared secret...
		└─Step.4 Use the symmetric key to decrypt the value of the data key -> PaymentDataDecrypter.decrypt(keyMaterial, applePayData);
		 	└decrypted!!!
	


前端實作:

	html透過safari的ApplePaySession確認此設備中的wallet中是否有綁定信用卡，有則會顯示apple pay radio btn。

	Apple Pay Merchant Identifier 底家啦
![image](https://github.com/JhengTom/applePay/blob/master/image1.png)

```JAVA
<script src="https://applepay.cdn-apple.com/jsapi/v1/apple-pay-sdk.js"></script>
<script language="JavaScript"> 
 /* 檢查當前瀏覽器是否支援Apple Pay */ 
 if (window.ApplePaySession) { 
	 //console.log("檢查當前瀏覽器是否支援Apple Pay"); 
	 //console.log(window.ApplePaySession); 
 	var merchantIdentifier = '<%=merchantID%>'; //填入你申請的Apple Pay Merchant Identifier
 	/* 檢查設備是否能夠支援Apple Pay付款，它不會驗證用戶在電子錢包中是否有綁定卡片 */ 
 	if (ApplePaySession.canMakePayments()) { 
 		/* 檢查付款設備是否能夠支援Apple Pay付款，且用戶在電子錢包中必需綁定一張卡片 */ 
 		/* 若Safari設定中的「檢查ApplePay設定」關閉時canMakePayments一律回傳True */ 
 		var promise = ApplePaySession.canMakePaymentsWithActiveCard(merchantIdentifier); 
 		 //console.log(promise); 
 		promise.then(function (canMakePayments) {		 
 			// console.log(canMakePayments); 
 			if (canMakePayments) { 
 			//顯示ApplePay按鈕 
 				document.getElementById("doApple").style.display="" 
 			}else { 
 			/* 無綁定卡片無法進行ApplyPay*/ 
 			/* 執行錯誤提示或進行頁面跳轉*/ 
 			} 
 		}); 
 	}else { 
 	/* 此設備不支援ApplePay */ 
 	/* 執行錯誤提示或進行頁面跳轉 */ 
 	} 
  } else { 
 	/* 無法支援Apple Pay的相關處理 */ 
 	/* 執行錯誤提示或進行頁面跳轉 */ 
  }  
  	

```

submit時將訂單資訊(品名，金額) 建立 ApplePaySession後，由safari呼叫html中的appleSession.onvalidatemerchant方法將需要驗證資料傳到後端ApplePayAction.checkMerchant判斷MerchantId。
對應畫面:跳出付款視窗，但是指紋處還在載入。

appleSession.onvalidatemerchant 的MerchantId驗證成功(ajax success)後，將回傳參數帶到appleSession.completeMerchantValidation中，交由appleSession觸發appleSession.onpaymentauthorized 付款授權驗證。
對應畫面:付款成功，幾秒後自動關閉付款視窗。
```JAVA
function doApple (){ 
  	/* 建立 PaymentRequest */ 
  	/* 參考: https://developer.apple.com/reference/applepayjs/paymentrequest */ 
  	var request = { 
  		 countryCode: 'TW', //國家代碼請填 TW 
  		 currencyCode: 'TWD',//幣別僅接受 TWD 
  		 supportedNetworks: ['visa', 'masterCard','jcb'],//卡別僅支援 visa masterCard jcb 
  		 merchantCapabilities: ['supports3DS'], //付款方式僅支援 supports3DS 
  		 lineItems: [{ label: '測試商品', amount: '1900' }],//商品資訊 
  		 total: { label: 'PayNow,Inc', amount: '2030' } //商品統計 
  	}; 
//  	console.log(request); 
//  	var ver =window.ApplePaySession.supportsVersion(3) 
//	alert(ver) 
  	 
  	/* 建立 ApplePaySession */ 
 	/* 參考:https:/developer.apple.com/reference/applepayjs/applepaysession/2320659-applepaysession */ 
  	/*這邊的版本其實影響不大，safari向下兼容，所以你只要不超過你現在的safari版本都沒什麼問題*/ 
 	var appleSession = new ApplePaySession(3, request); 
  	appleSession.begin(); 
  	 
	/* 商店驗證事件 */ 
	appleSession.onvalidatemerchant = function (event) { 
	//	console.log(event.validationURL); 
	 var data = { 
			 act: 'checkMerchant', 
			 validationURL: event.validationURL 
			 }; 
			 /* 將validationURL拋到Server端，由Server端與Apple Server做商店驗證 */ 
	$.ajax({ 
		url: '<%=request.getContextPath()%>/action/applePayAction.do', 
		type: "POST", 
		data: data, 
		error: function (err) { 
			/* 執行錯誤提示或進行頁面跳轉*/ 
			appleSession.abort(); 
			}, 
		success: function(merchantSession){ 
			//console.log('merchantSession is a', typeof(merchantSession), merchantSession); // says: object 
			/* 取得Server回傳資訊 */  
			/* 後端驗證成功取得Merchant Session物件後，將物件pass給ApplePaySession */ 
			appleSession.completeMerchantValidation(JSON.parse(merchantSession));  
			} 
		}) 
	} 
	/* 付款授權事件 */ 
	appleSession.onpaymentauthorized = function (event) { 
		//console.log('event.payment is a', typeof(event.payment), event.payment); // says: object 
		//console.log('JSON.stringify(event.payment) is a', typeof(JSON.stringify(event.payment)), JSON.stringify(event.payment)); // says: object 
		var data = { 
				act: 'checkPayment', 
				payment: JSON.stringify(event.payment), 
		}; 
	 /* 將payment物件拋至Server端，由Server端處理交易授權 */ 
	 $.ajax({ 
			url: '<%=request.getContextPath()%>/action/applePayAction.do', 
			type : "POST", 
			data : data, 
			error : function(err) { 
				alert(JSON.stringify(err)); 
			}, 
			success : function(result) { 
				//console.log('result is a', typeof (result), result); // says: object 
				/* 依授權結果決定帶入ApplePaySession的回應 */ 
				// 授權成功 
				appleSession.completePayment(JSON.parse(ApplePaySession.STATUS_SUCCESS)); 
				// 授權失敗 
				appleSession.completePayment(JSON.parse(ApplePaySession.STATUS_FAILURE)); 
				} 
			}) 
		} 
	} 
</script>
```


後端程式:   

	1. act : 'checkMerchant'
		1.MerchantId Validate: use MerchantId-test.p12 
```JAVA
package ApplePayMerchantIdValidate; 
import java.io.BufferedReader; 
import java.io.BufferedWriter; 
import java.io.File; 
import java.io.FileInputStream; 
import java.io.IOException; 
import java.io.InputStream; 
import java.io.InputStreamReader; 
import java.io.OutputStream; 
import java.io.OutputStreamWriter; 
import java.net.URL; 
import java.net.URLEncoder; 
import java.security.KeyManagementException; 
import java.security.KeyStore; 
import java.security.KeyStoreException; 
import java.security.NoSuchAlgorithmException; 
import java.security.SecureRandom; 
import java.security.UnrecoverableKeyException; 
import java.security.cert.CertificateException; 
import javax.net.ssl.HttpsURLConnection; 
import javax.net.ssl.KeyManagerFactory; 
import javax.net.ssl.SSLContext; 
import javax.net.ssl.SSLSocketFactory;

public class ApplePayMerchantIdValidater { 
	private static final String ROOT_CER = "D:\\xxxxxx\\xxxxxx\\xxxxxx\\"; 
	private static final String MERCHANT_ID_P12 = "ApplePayMerchantId.p12"; 
	private static final String MERCHANT_ID_PASS = "xxxxxx"; 
	public String validate(String validationURL) { 
//		String validationURL = "https://apple-pay-gateway-cert.apple.com/paymentservices/startSession"; 
		URL url; 
		String UTF8 = "UTF-8"; 
		String merchantIdentifier = "xxxxxx"; 
		String domainName = "xxxxxx"; 
		String displayName = "xxxxxx"; 
		try { 
			String jsonBody = String.format("{\"merchantIdentifier\":\"%s\",\"domainName\":\"%s\",\"displayName\":\"%s\"}", 
					URLEncoder.encode(merchantIdentifier, UTF8), URLEncoder.encode(domainName, UTF8), 
					URLEncoder.encode(displayName, UTF8)); 
//			System.out.println("query"); 
//			System.out.println(query); 
			byte[] postData = jsonBody.getBytes(UTF8); 
			int postDataLength = postData.length; 
			url = new URL(validationURL); 
			HttpsURLConnection con = (HttpsURLConnection) url.openConnection(); 
			con.setRequestMethod("POST"); 
			con.setRequestProperty("Content-Type", "application/json; charset=UTF-8"); 
			con.setRequestProperty("Accept", "application/json"); 
			con.setRequestProperty("Content-Length", Integer.toString(postDataLength)); 
			con.setDoOutput(true); 
			con.setDoInput(true); 
			File pKeyFile = new File(ROOT_CER + MERCHANT_ID_P12); 
			KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509"); 
			KeyStore keyStore = KeyStore.getInstance("PKCS12"); 
			InputStream keyInput = new FileInputStream(pKeyFile); 
			keyStore.load(keyInput, MERCHANT_ID_PASS.toCharArray()); 
			keyInput.close(); 
			keyManagerFactory.init(keyStore, MERCHANT_ID_PASS.toCharArray()); 
			SSLContext context = SSLContext.getInstance("TLSv1.2"); 
			context.init(keyManagerFactory.getKeyManagers(), null, new SecureRandom()); 
			SSLSocketFactory sockFact = context.getSocketFactory(); 
			con.setSSLSocketFactory(sockFact); 
			// 輸出 
			OutputStream os = con.getOutputStream(); 
			OutputStreamWriter osw = new OutputStreamWriter(os); 
			BufferedWriter bw = new BufferedWriter(osw); 
			bw.write(jsonBody); 
			bw.flush(); 
			bw.close(); 
			osw.close(); 
			os.close(); 
			// 輸入 
			InputStream in = con.getInputStream(); 
			InputStreamReader isr = new InputStreamReader(in, UTF8); 
			BufferedReader br = new BufferedReader(isr); 
			String line; 
			StringBuilder sb = new StringBuilder(); 
			while ((line = br.readLine()) != null) { 
				sb.append(line); 
			} 
			br.close(); 
			isr.close(); 
			in.close(); 
			System.out.println("uew POST meyhod get apple merchant object： " + sb.toString()); 
			return sb.toString(); 
			/** 
			 * apple merchant json body = sb： 
			 * { 
			 * "epochTimestamp": 164967xxxxxx9, 
			 * "expiresAt": 16496xxxxxx99, 
			 * "merchantSessionIdentifier":"SSH0C93067174574xxxxxx8DAxxxxxx6xxxxxxxxxxxxED1343Fxxxxxx5E12BEE925xxxxxx1A17C46B0DE5A943F0F94927C24", 
			 * "nonce": "774a8c10", 
			 * "merchantIdentifier":"03047015415Bxxxxxx4E37536EAxxxxxx7A2E06xxxxxx42CB6xxxxxx16xxxxxx", 
			 * "domainName": "xxxxxx", 
			 * "displayName": "xxxxxxTest", 
			 * "signature": "xxxxxxxxxxxxxxxxxxxxxxxxxxx", 
			 * "operationalAnalyticsIdentifier": "xxxxxx:03047xxxxxxBCxxxxxxE37xxxxxxD03C7A2E06F0AEBxxxxxx06312Dxxxxxx55", 
			 * "retries": 0, 
			 * "pspId": "03047015415BC3CE434ExxxxxxAF6D03Cxxxxxxxxxxxx42CB6xxxxxx16409155" 
			 * } 
			 *  
			 */ 
		} catch (IOException | NoSuchAlgorithmException | KeyStoreException | KeyManagementException 
				| UnrecoverableKeyException | CertificateException e) { 
			// TODO Auto-generated catch block 
			e.printStackTrace(); 
		} 
		return ""; 
	} 
}
```
	2. act : 'checkPayment'
		2.Payment Processing: use ProcessingCert.p12 and AppleRootCA-G3.cer
		├─Step.1 Verify the signature -> SignatureVerifier.validate(applePayData, applePayPaymentHe ader, applePaySignature,APPLE_PAY_SIGNATURE_EXPIRATION_IN_MS);
		│	├step 1.1: Ensure that the certificates contain the correct custom OIDs	
		│	├step 1.2: Ensure that the root CA is the Apple Root CA - G3
		│	├step 1.3: Ensure that there is a valid X.509 chain of trust from the signature to the root CA. Specifically
		│	├step 1.4: Ensure that the signature is a valid ECDSA signature
		│	└step 1.5: Inspect the CMS signing time of the signature
		├─Step.2 Determine which merchant public key was use -> PublicKeyHashVerifier.validate(publicKeyHash);
		│	└step 2.1: checkPublicKeyHash
		├─Step.3 Restore the symmetric key -> RestoreSymmetricKey.decrypt(applePayPaymentHeader);
		│	├step 3.1: a. Use the merchant private key and the ephemeral public key...
		│	└step 3.2: b. Use the merchant identifier field (OID 1.2.840.113635.100.6.32) of the public key certificate and the shared secret...
		└─Step.4 Use the symmetric key to decrypt the value of the data key -> PaymentDataDecrypter.decrypt(keyMaterial, applePayData);
		 	└decrypted!!!
		

payment decrypte master: <br>
<br>
注意 解密完其實不用回傳，只需存在起來就好(因為這是apple pay付完款後的資料)。<br>
		Step.1 Verify the signature<br>
		Step.2 Determine which merchant public key was use<br>
		Step.3 Restore the symmetric key<br>
		Step.4 Use the symmetric key to decrypt the value of the data key<br>

```JAVA
package ApplePay.appelPayPaymentDecrypt;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import ApplePay.appelPayPaymentDecrypt.ApplePayPaymentToken.Token.PaymentData.Header;

/**
 * Example implementation of Apple Pay signature verification 
 */
public class ApplePayPaymentDecrypter {
	private static final String paymentTokenJsonData = "{\"token\":{\"paymentData\":{\"data\":\"xMrq8xxxxxxxxxxyCzMvECQ2nbvW57ohshu2bnLrryEVl/UFlwxdkOlhLxvvegbUL21s3eIjEvhhqWv7tPgDVaiUI1055oxHFEwTCOWBFHFlQkGEmmyjPjCGE91PaeTxxxxxxEfShs4JwCdZxxxxkwjgP9vK48HubxxxxxxxxLkEF60bpQxxxxxxQ5sJd/IXxxxxxxxxxxxxxxxxxxGFPuPXqd2CSLk5M02AzxxxxxxxxxxxxxxxxxxVmDuJQIyPtKXfzIVL6FYf9SIyzACNDTRk/yQvig0uyCeSvM+JhareJoXHJCC9KnzhU5U7ZjScLynEoL9EztAgUxxxxxxxxxxxxbtiptpNlzU0w3QXvgKYHNMPlmxxxxxxUFxeRBV4cWft16wxxxxxx8MQalMA\",\"signature\":\"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\",\"header\":{\"publicKeyHash\":\"xxxxxxxxxxxxxxxxxxg=\",\"ephemeralPublicKey\":\"MFxxxxxxxxxxxxxxxxxxKoZIzj0DAQcDQgAEiSa+gvC/mlDqbmWKyn3oi9A/sjzl7x832+2PpGyENu5F6F1JNp6qCJ3wJjN9Kt8UNUSxxxxxxxxxxxxxxxxxxw==\",\"transactionId\":\"342b313dfbbc08d15ee88ce064ff3b9510367fd9625059fa127a4f16xxxxxx39\"},\"version\":\"EC_v1\"},\"paymentMethod\":{\"displayName\":\"MasterCard 1470\",\"network\":\"MasterCard\",\"type\":\"credit\"},\"transactionIdentifier\":\"342B31xxxxxx08D15EE88CE064xxxxxx10367FD9625059FA127A4F1xxxxxxF39\"}}";
	private static final String BC = "BC";
	private static final String EC_V_1 = "EC_v1";
	private static final String ROOT_CER = "D:\\xxxxxx\\xxxxxx\\xxxxxx\\";
	private static final String PAY_PROCESSING_P12 = "ApplePayPayProcessingCert.p12";
	private static final String PAY_PROCESSING_PASS = "xxxxxx";
	private static final String PAY_PROCESSING_ALIAS_NAME = "xxxxxx";
	private static final String APPLE_ROOT_CA_G3_CER = "ApplePay/AppleRootCA-G3.cer";
	private static final int APPLE_PAY_SIGNATURE_EXPIRATION_IN_MS = 60 * 1000;

	public static void main(String[] args) throws Exception {
		if (Security.getProvider(BC) == null) {
			Security.addProvider(new BouncyCastleProvider());
		}
		ApplePayPaymentToken applePayPaymentToken = CreateApplePayPaymentToken(paymentTokenJsonData);
		String applePayData = applePayPaymentToken.getToken().getPaymentData().getData();
		String applePaySignature = applePayPaymentToken.getToken().getPaymentData().getSignature();
		String applePayVersion = applePayPaymentToken.getToken().getPaymentData().getVersion();
		Header applePayPaymentHeader = applePayPaymentToken.getToken().getPaymentData().getHeader();
		if (!applePayVersion.equals(EC_V_1)) {
			throw new Exception("Apple pay signature verification supported only for version " + EC_V_1);
		}
		// Step.1 Verify the signature 
		SignatureVerifier.validate(applePayData, applePayPaymentHeader, applePaySignature,
				APPLE_PAY_SIGNATURE_EXPIRATION_IN_MS, APPLE_ROOT_CA_G3_CER, ROOT_CER);
		// Step.2 Determine which merchant public key was use 
		String publicKeyHash = applePayPaymentHeader.getPublicKeyHash();
		PublicKeyHashVerifier.validate(publicKeyHash, PAY_PROCESSING_P12, PAY_PROCESSING_PASS, ROOT_CER);
		// Step.3 Restore the symmetric key 
		byte[] keyMaterial = RestoreSymmetricKey.decrypt(applePayPaymentHeader, PAY_PROCESSING_P12, PAY_PROCESSING_PASS,
				PAY_PROCESSING_ALIAS_NAME, ROOT_CER);
		// Step.4 Use the symmetric key to decrypt the value of the data key 
		PaymentDataDecrypter.decrypt(keyMaterial, applePayData);
	}

	private static ApplePayPaymentToken CreateApplePayPaymentToken(String paymentTokenBody) {
		Gson gson = new Gson();
		java.lang.reflect.Type type = new TypeToken<ApplePayPaymentToken>() {
		}.getType();
		ApplePayPaymentToken applePayPaymentToken = gson.fromJson(paymentTokenBody, type);
		return applePayPaymentToken;
	}
}
```

// Step.1 Verify the signature

```JAVA
package ApplePay.appelPayPaymentDecrypt;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertStore;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1UTCTime;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import ApplePay.appelPayPaymentDecrypt.ApplePayPaymentToken.Token.PaymentData.Header;

// Validating apple pay signature according to 
// https://developer.apple.com/library/prerelease/ios/documentation/PassKit/Reference/PaymentTokenJSON/PaymentTokenJSON.html 
public class SignatureVerifier {
	private static final String BC = "BC";
	private static final String LEAF_OID = "1.2.840.113635.100.6.29";
	private static final String INTERMEDIATE_OID = "1.2.840.113635.100.6.2.14";
	private static final String PKIX = "PKIX";
	private static final String COLLECTION = "Collection";
	private static final String X_509 = "X.509";

	public static void validate(String applePayData, Header applePayHeader, String applePaySignature,
								long applePaySignatureExpirationInMs, String APPLE_ROOT_CA_G3_CER, String ROOT_CER) throws Exception {
		byte[] signedData = getSignedData(applePayData, applePayHeader);
		CMSSignedData cmsSignedData = new CMSSignedData(new CMSProcessableByteArray(signedData),
				Base64.decode(applePaySignature));
		Store store = cmsSignedData.getCertificates();
		ArrayList<X509CertificateHolder> allCertificates = (ArrayList<X509CertificateHolder>) store.getMatches(null);
		ArrayList signers = (ArrayList) cmsSignedData.getSignerInfos().getSigners();
		SignerInformation signerInformation = (SignerInformation) signers.get(0);
		List<X509Certificate> x509Certificates = new ArrayList();
		for (X509CertificateHolder certificate : allCertificates) {
			x509Certificates.add(new JcaX509CertificateConverter().setProvider(BC).getCertificate(certificate));
		}
		// step 1: 確保簽名當中包含正確的custom OIDs 
		// Ensure that the certificates contain the correct custom OIDs: 
		// 1.2.840.113635.100.6.29 
		// for the leaf certificate and 1.2.840.113635.100.6.2.14 for the intermediate 
		// CA. The value for these marker OIDs doesn’t matter, only their presence. 
		validateCustomData(allCertificates);
		InputStream inputStream = null;
		X509Certificate appleRootCertificate = null;
		// step 2: 官方Root CA 
		// Ensure that the root CA is the Apple Root CA - G3. This certificate is 
		// available from apple.com/certificateauthority. 
		try {
			File cerFile = new File(ROOT_CER + APPLE_ROOT_CA_G3_CER);
			inputStream = new FileInputStream(cerFile);
			CertificateFactory certificateFactory = CertificateFactory.getInstance(X_509);
			appleRootCertificate = (X509Certificate) certificateFactory.generateCertificate(inputStream);
		} finally {
			IOUtils.closeQuietly(inputStream);
		}
		// step 3:確認x.509 chain of trust可以一路追朔到Apple Root CA -G3 
		// Ensure that there is a valid X.509 chain of trust from the signature to the 
		// root CA. Specifically, 
		// ensure that the signature was created using the private key corresponding to 
		// the leaf certificate, 
		// that the leaf certificate is signed by the intermediate CA, and that the 
		// intermediate CA is signed by the Apple Root CA - G3. 
		verifyCertificate(x509Certificates.get(0), appleRootCertificate, x509Certificates);
		// step 4: 驗證簽名 
		// Ensure that the signature is a valid ECDSA signature (ecdsa-with-SHA256 
		// 1.2.840.10045.4.3.2) of the 
		// concatenated values of the ephemeralPublicKey, data, transactionId, and 
		// applicationData keys. 
		validateSignature(signerInformation, store);
		// step 5:檢查簽發時間 
		// Inspect the CMS signing time of the signature, as defined by section 11.3 of 
		// RFC 5652. 
		// If the time signature and the transaction time differ by more than a few 
		// minutes, it's possible that the token is a replay attack. 
		validateSignatureTime(applePaySignatureExpirationInMs, signerInformation);
	}

	/**
	 * 確保簽名當中包含正確的custom OIDs， 
	 *
	 * @param allCertificates
	 * @throws Exception
	 */
	private static void validateCustomData(ArrayList<X509CertificateHolder> allCertificates) throws Exception {
//		System.out.println(allCertificates.get(0).getExtension(new ASN1ObjectIdentifier(LEAF_OID))); 
//		System.out.println(allCertificates.get(1).getExtension(new ASN1ObjectIdentifier(INTERMEDIATE_OID))); 
		if (allCertificates.size() != 2) {
			throw new Exception("signature certificates count expected 2, but it's :" + allCertificates.size());
		}
		if (allCertificates.get(0).getExtension(new ASN1ObjectIdentifier(LEAF_OID)) == null) {
			throw new Exception("leaf certificate doesn't have extension: " + LEAF_OID);
		}
		if (allCertificates.get(1).getExtension(new ASN1ObjectIdentifier(INTERMEDIATE_OID)) == null) {
			throw new Exception("intermediate certificate doesn't have extension: " + INTERMEDIATE_OID);
		}
	}

	/**
	 * 驗證簽名 
	 *
	 * @param signerInformation
	 * @param store
	 * @return boolean
	 * @throws Exception
	 */
	private static boolean validateSignature(SignerInformation signerInformation, Store store) throws Exception {
		try {
			ArrayList certCollection = (ArrayList) store.getMatches(signerInformation.getSID());
			Iterator certIt = certCollection.iterator();
			X509CertificateHolder certHolder = (X509CertificateHolder) certIt.next();
			X509Certificate cert = new JcaX509CertificateConverter().setProvider(BC).getCertificate(certHolder);
			return signerInformation.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(cert));
		} catch (Exception ex) {
			throw new Exception("Failed to verify apple pay signature, the result is false");
		}
	}

	/**
	 * 檢查簽章時間 
	 *
	 * @param applePaySignatureExpirationInMs
	 * @param signerInformation
	 * @throws Exception
	 */
	private static void validateSignatureTime(long applePaySignatureExpirationInMs, SignerInformation signerInformation)
			throws Exception {
		long signDate = 0;
		AttributeTable signedAttributes = signerInformation.getSignedAttributes();
		Attribute signingTime = signedAttributes.get(CMSAttributes.signingTime);
		Enumeration signingTimeObjects = signingTime.getAttrValues().getObjects();
		if (signingTimeObjects.hasMoreElements()) {
			Object signingTimeObject = signingTimeObjects.nextElement();
			if (signingTimeObject instanceof ASN1UTCTime) {
				ASN1UTCTime asn1Time = (ASN1UTCTime) signingTimeObject;
				signDate = asn1Time.getDate().getTime();
			}
		}
		if (signDate == 0) {
			throw new Exception("Failed to extract sign time from apple pay signature.");
		}
		long expiration = System.currentTimeMillis() - applePaySignatureExpirationInMs;
		if (expiration > signDate) {
			throw new Exception("apple pay signature is too old, the expiration time is: "
					+ applePaySignatureExpirationInMs + " ms");
		}
	}

	/**
	 * 確認x.509 chain of trust可以一路追朔到Apple Root CA -G3 
	 *
	 * @param leafCertificate
	 * @param trustedRootCert
	 * @param intermediateCerts
	 * @throws Exception
	 */
	private static void verifyCertificate(X509Certificate leafCertificate, X509Certificate trustedRootCert,
										  List<X509Certificate> intermediateCerts) throws Exception {
		try {
			// Create the selector that specifies the starting certificate 
			X509CertSelector selector = new X509CertSelector();
			selector.setCertificate(leafCertificate);
			// Create the trust anchors (set of root CA certificates) 
			Set<TrustAnchor> trustAnchors = new HashSet<TrustAnchor>();
			trustAnchors.add(new TrustAnchor(trustedRootCert, null));
			// Configure the PKIX certificate builder algorithm parameters 
			PKIXBuilderParameters pkixParams = new PKIXBuilderParameters(trustAnchors, selector);
			// Disable CRL checks (this is done manually as additional step) 
			pkixParams.setRevocationEnabled(false);
			// Specify a list of intermediate certificates 
			CertStore intermediateCertStore = CertStore.getInstance(COLLECTION,
					new CollectionCertStoreParameters(intermediateCerts), BC);
			pkixParams.addCertStore(intermediateCertStore);
			// Build and verify the certification chain 
			CertPathBuilder builder = CertPathBuilder.getInstance(PKIX, BC);
			// If no exception thrown, it means the validation passed. 
			PKIXCertPathBuilderResult pkixCertPathBuilderResult = (PKIXCertPathBuilderResult) builder.build(pkixParams);
		} catch (Exception ex) {
			throw new Exception("Failed to validate chain of trust for apple certificates.");
		}
	}

	private static byte[] getSignedData(String applePayData, Header applePayHeader) throws IOException {
		byte[] ephemeralPublicKeyBytes = Base64.decode(applePayHeader.getEphemeralPublicKey());
		byte[] applePayDataBytes = Base64.decode(applePayData);
		byte[] transactionIdBytes = Hex.decode(applePayHeader.getTransactionId());
		byte[] applicationDataBytes = null;
		if (!StringUtils.isEmpty(applePayHeader.getApplicationData())) {
			applicationDataBytes = Base64.decode(applePayHeader.getApplicationData());
		}
		ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
		byteArrayOutputStream.write(ephemeralPublicKeyBytes);
		byteArrayOutputStream.write(applePayDataBytes);
		byteArrayOutputStream.write(transactionIdBytes);
		if (applicationDataBytes != null) {
			byteArrayOutputStream.write(applicationDataBytes);
		}
		return byteArrayOutputStream.toByteArray();
	}
}
```




// Step.2 Determine which merchant public key was use

```JAVA
package ApplePay.appelPayPaymentDecrypt;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.DigestException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Objects;

/**
 * Payment Processing Certificate. A certificate used to securely transfer 
 * payment data. Apple Pay servers use the payment processing certificate’s 
 * public key to encrypt the payment data. Use the private key to decrypt the 
 * data when processing payments. 
 *
 * Important things to say three times 
 *
 * Apple Pay servers use the payment processing certificate’s public key to 
 * encrypt the payment data. 
 * Apple Pay servers use the payment processing certificate’s public key to 
 * encrypt the payment data. 
 * Apple Pay servers use the payment processing certificate’s public key to 
 * encrypt the payment data. 
 *
 * @author devadmin
 *
 */
public class PublicKeyHashVerifier {
	public static void validate(String publicKeyHash, String PAY_PROCESSING_P12, String PAY_PROCESSING_PASS, String ROOT_CER)
			throws Exception {
		File cerFile = new File(ROOT_CER + PAY_PROCESSING_P12);
		InputStream keyInput = new FileInputStream(cerFile);
		KeyStore keyStore = KeyStore.getInstance("PKCS12");
		try {
			keyStore.load(keyInput, PAY_PROCESSING_PASS.toCharArray());
		} catch (Exception e) {
			e.printStackTrace();
		}
		String alias = keyStore.aliases().nextElement();
		X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias);
		checkPublicKeyHash(publicKeyHash, certificate);
		keyInput.close();
	}

	private static void checkPublicKeyHash(String publicKeyHash, X509Certificate paymentProcessingCertificate)
			throws NoSuchAlgorithmException, CertificateException, DigestException {
		String certHash = Base64.getEncoder().encodeToString(
				MessageDigest.getInstance("SHA-256").digest(paymentProcessingCertificate.getPublicKey().getEncoded()));
		if (!Objects.equals(publicKeyHash, certHash)) {
			throw new DigestException(String.format(
					"publicKeyHash %s doesn't match Payment Processing Certificate hash %s", publicKeyHash, certHash));
		}
	}
}
```




// Step.3 Restore the symmetric key

```JAVA
package ApplePay.appelPayPaymentDecrypt;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.KeyAgreement;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.util.encoders.Hex;
import ApplePay.appelPayPaymentDecrypt.ApplePayPaymentToken.Token.PaymentData.Header;

/*** 
 * Payment Processing Certificate. A certificate used to securely transfer 
 * payment data. Apple Pay servers use the payment processing certificate’s 
 * public key to encrypt the payment data. Use the private key to decrypt the 
 * data when processing payments. 
 *
 * Important things to say three times 
 *
 * Use the private key to decrypt the data when processing payments. 
 * Use the private key to decrypt the data when processing payments. 
 * Use the private key to decrypt the data when processing payments. 
 *
 * @author devadmin
 *
 */
public class RestoreSymmetricKey {
	private static final String CERTIFICATE_OID = "1.2.840.113635.100.6.32";
	private static final String ID_AES256_GCM = "id-aes256-GCM";
	private static final String APPLE = "Apple";

	public static byte[] decrypt(Header applePayPaymentHeader, String PAY_PROCESSING_P12, String PAY_PROCESSING_PASS,
								 String PAY_PROCESSING_ALIAS_NAME, String ROOT_CER) {
		File cerFile = new File(ROOT_CER + PAY_PROCESSING_P12);
		byte[] keyMaterial;
		try {
			InputStream keyInput = new FileInputStream(cerFile);
			KeyStore keyStore = KeyStore.getInstance("PKCS12");
			keyStore.load(keyInput, PAY_PROCESSING_PASS.toCharArray());
			Key key = null;
			key = keyStore.getKey(PAY_PROCESSING_ALIAS_NAME, PAY_PROCESSING_PASS.toCharArray());
			Certificate cert = keyStore.getCertificate(PAY_PROCESSING_ALIAS_NAME);
			// Merchant CERTIFICATE 
//			String cerString = Base64.getEncoder().encodeToString(cert.getEncoded());// 取的ca 
//			System.out.println("cerString==" + cerString); 
			// PUBLIC 
//		String publicKeyString = Base64.getEncoder().encodeToString(cert.getPublicKey().getEncoded());// 取得公鑰 
//		System.out.println("publicKeyString==" + publicKeyString); 
			// PRIVATE 
//			String privateKeyString = Base64.getEncoder().encodeToString(key.getEncoded());// 取得私鑰 
//			System.out.println("privateKeyString==" + privateKeyString); 
//			System.out.println(mstr); 
			// a. Use the merchant private key and the ephemeral public key, to generate the 
			// shared secret using Elliptic Curve Diffie-Hellman (id-ecDH 1.3.132.1.12). 
			final byte[] keyData = org.bouncycastle.util.encoders.Base64
					.decode(applePayPaymentHeader.getEphemeralPublicKey());
			X509EncodedKeySpec ks = new X509EncodedKeySpec(keyData);
			KeyFactory kf = KeyFactory.getInstance("EC");
			ECPublicKey ephemeralPublicKey = (ECPublicKey) kf.generatePublic(ks);
			KeyAgreement aKeyAgree = KeyAgreement.getInstance("ECDH");
			aKeyAgree.init((ECPrivateKey) key);
			aKeyAgree.doPhase(ephemeralPublicKey, true);
			byte[] sharedSecret = aKeyAgree.generateSecret();
//			System.out.println("sharedSecret Base64.getEncoder=>?" + Base64.getEncoder().encodeToString(sharedSecret)); 
			// b. Use the merchant identifier field (OID 1.2.840.113635.100.6.32) of the 
			// public key certificate and the shared secret, to derive the symmetric key 
			// using the key derivation function described in NIST SP 800-56A, section 
			// 5.8.1, with the following input values: 
			byte[] algorithmId = ((char) 0x0D + ID_AES256_GCM).getBytes("ASCII");
			byte[] partyUInfo = APPLE.getBytes("ASCII");
			byte[] partyVInfo = extractMerchantIdFromCertificateOid(CERTIFICATE_OID, (X509Certificate) cert);
			byte[] otherInfo = new byte[algorithmId.length + partyUInfo.length + partyVInfo.length];
			System.arraycopy(algorithmId, 0, otherInfo, 0, algorithmId.length);
			System.arraycopy(partyUInfo, 0, otherInfo, algorithmId.length, partyUInfo.length);
			System.arraycopy(partyVInfo, 0, otherInfo, algorithmId.length + partyUInfo.length, partyVInfo.length);
			keyMaterial = kdf(sharedSecret, otherInfo);
//			System.out.println("keyMaterial(aka symmetric key)=" + Base64.getEncoder().encodeToString(keyMaterial)); 
			return keyMaterial;
		} catch (FileNotFoundException e1) {
			// TODO Auto-generated catch block 
			e1.printStackTrace();
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block 
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block 
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block 
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block 
			e.printStackTrace();
		} catch (UnrecoverableKeyException e) {
			// TODO Auto-generated catch block 
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block 
			e.printStackTrace();
		} catch (IllegalStateException e) {
			// TODO Auto-generated catch block 
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block 
			e.printStackTrace();
		}
		return null;
	}

	protected static byte[] kdf(byte[] z, byte[] otherInfo) throws NoSuchAlgorithmException {
		Digest digest = new SHA256Digest();
		byte[] result = new byte[digest.getDigestSize()];
		digest.update((byte) (1 >> 24));
		digest.update((byte) (1 >> 16));
		digest.update((byte) (1 >> 8));
		digest.update((byte) 1);
		digest.update(z, 0, z.length);
		digest.update(otherInfo, 0, otherInfo.length);
		digest.doFinal(result, 0);
		return result;
	}

	protected static byte[] extractMerchantIdFromCertificateOid(String oid, X509Certificate cert)
			throws UnsupportedEncodingException {
		byte[] merchantIdentifierTlv = cert.getExtensionValue(oid);
		byte[] merchantIdentifier = new byte[64];
		System.arraycopy(merchantIdentifierTlv, 4, merchantIdentifier, 0, 64);
		return Hex.decode(merchantIdentifier);
	}
}
```




// Step.4 Use the symmetric key to decrypt the value of the data key

```JAVA
package ApplePay.appelPayPaymentDecrypt;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class PaymentDataDecrypter {
	private final static byte[] iv = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00};

	public static void decrypt(byte[] keyMaterial, String applePayData) {
		try {
			Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
			cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(keyMaterial, "AES"), new IvParameterSpec(iv));
			byte[] encryptedData = org.bouncycastle.util.encoders.Base64.decode(applePayData);
			byte[] decryptedData = cipher.doFinal(encryptedData);
			String ff = new String(decryptedData, "ASCII");
			System.out.println(ff);
		} catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException e) {
			// TODO Auto-generated catch block 
			e.printStackTrace();
		} catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block 
			e.printStackTrace();
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			// TODO Auto-generated catch block 
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block 
			e.printStackTrace();
		}
	}
}

ff=解碼出來的panment
		{
		"applicationPrimaryAccountNumber":"5204xxxxx0372732",
		"applicationExpirationDate":"220930",
		"currencyCode":"901", //TWD 
		"transactionAmount":203000,
		"deviceManufacturerIdentifier":"05011xxxxx73",
		"paymentDataType":"3DSecure",
		"paymentData":{
		"onlinePaymentCryptogram":"AFVgYRiBESpjxxxxxsngAoABFA=="
		}
		}
```



另外說明:


雷區:

[Payment Token Format Reference | Apple Developer Documentation](https://developer.apple.com/documentation/passkit/apple_pay/payment_token_format_reference)<br>

這邊說
![image](https://github.com/JhengTom/applePay/blob/master/image2.png)<br>
[https://developer.apple.com/documentation/passkit/apple_pay/setting_up_apple_pay](https://developer.apple.com/documentation/passkit/apple_pay/setting_up_apple_pay)<br>
<br>
![image](https://github.com/JhengTom/applePay/blob/master/image3.png)<br>
`apple use the payment processing certificate’s public key to encrypt the payment data`<br>
雷阿 所以你這邊要用payment processing certificate，而不是上面說的merchant certificate<br>

真di4GY<br>
---

憑證

Openssl 安裝:[Win32/Win64 OpenSSL Installer for Windows - Shining Light Productions (slproweb.com)](https://slproweb.com/products/Win32OpenSSL.html)<br>
- 如果npm版本過舊安裝<br>
	- <<Win64OpenSSL-1_1_1n.msi>><br>
- Node.JS version 17  安裝<br>
	- <<Win64OpenSSL_Light-3_0_2.msi>><br>
---

確認是否要先喘成PEM好讓JAVA方便讀取憑證中的公鑰

先使用OPENSSL轉檔成pem確認公鑰
	先轉成pem
	openssl pkcs12 -in D:\xxxxxx_workspeace\testCode\bin\xxxxxxApplePayMerchantId-test.p12 -clcerts -nokeys -out D:\xxxxxx_workspeace\testCode\bin\xxxxxxApplePayMerchantId-test.pem
	再把pem中的
	openssl x509 -pubkey -in D:\xxxxxx_workspeace\testCode\bin\xxxxxxApplePayMerchantId-test.pem -noout > D:\xxxxxx_workspeace\testCode\bin\mypubkey.pem

![image](https://github.com/JhengTom/applePay/blob/master/image4.png)

再使用java確認公鑰
![image](https://github.com/JhengTom/applePay/blob/master/image5.png)


兩者相同!!! 所以不用轉來轉去，所以可以直接拿原本的p12來用<br>
	[Certificate Hash | Apple Developer Forums](https://developer.apple.com/forums/thread/20067)<br><br>
	[encryption - Apple Pay - How to compare merchant public key with publicKeyHash from payment token? - Stack Overflow](https://stackoverflow.com/questions/45040171/apple-pay-how-to-compare-merchant-public-key-with-publickeyhash-from-payment-t)<br>

---

