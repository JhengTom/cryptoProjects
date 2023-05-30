package applePay.appelPayPaymentDecrypt;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import applePay.appelPayPaymentDecrypt.ApplePayPaymentToken.Token.PaymentData.Header;

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

	private static final int APPLE_PAY_SIGNATURE_EXPIRATION_IN_MS = 60*1000;

	public static void main(String[] args) throws Exception {

		if (Security.getProvider(BC) == null) {
			Security.addProvider(new BouncyCastleProvider());
		}

		applePay.appelPayPaymentDecrypt.ApplePayPaymentToken applePayPaymentToken = CreateApplePayPaymentToken(paymentTokenJsonData);

		String applePayData = applePayPaymentToken.getToken().getPaymentData().getData();
		String applePaySignature = applePayPaymentToken.getToken().getPaymentData().getSignature();
		String applePayVersion = applePayPaymentToken.getToken().getPaymentData().getVersion();
		Header applePayPaymentHeader = applePayPaymentToken.getToken().getPaymentData().getHeader();
		if (!applePayVersion.equals(EC_V_1)) {
			throw new Exception("Apple pay signature verification supported only for version " + EC_V_1);
		}
		// Step.1 Verify the signature
		applePay.appelPayPaymentDecrypt.SignatureVerifier.validate(applePayData, applePayPaymentHeader, applePaySignature,
				APPLE_PAY_SIGNATURE_EXPIRATION_IN_MS, APPLE_ROOT_CA_G3_CER, ROOT_CER);

		// Step.2 Determine which merchant public key was use
		String publicKeyHash = applePayPaymentHeader.getPublicKeyHash();
		applePay.appelPayPaymentDecrypt.PublicKeyHashVerifier.validate(publicKeyHash, PAY_PROCESSING_P12, PAY_PROCESSING_PASS, ROOT_CER);

		// Step.3 Restore the symmetric key
		byte[] keyMaterial = RestoreSymmetricKey.decrypt(applePayPaymentHeader, PAY_PROCESSING_P12, PAY_PROCESSING_PASS,
				PAY_PROCESSING_ALIAS_NAME, ROOT_CER);

		// Step.4 Use the symmetric key to decrypt the value of the data key
		PaymentDataDecrypter.decrypt(keyMaterial, applePayData);
	}

	private static applePay.appelPayPaymentDecrypt.ApplePayPaymentToken CreateApplePayPaymentToken(String paymentTokenBody) {
		Gson gson = new Gson();
		java.lang.reflect.Type type = new TypeToken<applePay.appelPayPaymentDecrypt.ApplePayPaymentToken>() {
		}.getType();
		applePay.appelPayPaymentDecrypt.ApplePayPaymentToken applePayPaymentToken = gson.fromJson(paymentTokenBody, type);

		return applePayPaymentToken;
	}
}