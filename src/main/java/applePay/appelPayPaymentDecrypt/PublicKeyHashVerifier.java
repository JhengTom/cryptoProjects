package applePay.appelPayPaymentDecrypt;

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
 * payment data. Apple Pay servers use the payment processing certificate��s
 * public key to encrypt the payment data. Use the private key to decrypt the
 * data when processing payments.
 * 
 * Important things to say three times
 * 
 * Apple Pay servers use the payment processing certificate��s public key to
 * encrypt the payment data.
 * Apple Pay servers use the payment processing certificate��s public key to
 * encrypt the payment data.
 * Apple Pay servers use the payment processing certificate��s public key to
 * encrypt the payment data.
 * 
 * @author devadmin
 *
 */
public class PublicKeyHashVerifier {

	public static void validate(String publicKeyHash, String PAY_PROCESSING_P12, String PAY_PROCESSING_PASS,String ROOT_CER )
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
