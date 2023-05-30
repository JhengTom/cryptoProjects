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