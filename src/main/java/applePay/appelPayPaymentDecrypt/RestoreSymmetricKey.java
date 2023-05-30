package applePay.appelPayPaymentDecrypt;

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

import applePay.appelPayPaymentDecrypt.ApplePayPaymentToken.Token.PaymentData.Header;

/***
 * Payment Processing Certificate. A certificate used to securely transfer
 * payment data. Apple Pay servers use the payment processing certificate��s
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
	private static final String ID_AES256_GCM="id-aes256-GCM";
	private static final String APPLE="Apple";

	public static byte[] decrypt(Header applePayPaymentHeader, String PAY_PROCESSING_P12, String PAY_PROCESSING_PASS,
			String PAY_PROCESSING_ALIAS_NAME,String ROOT_CER ) {
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
//			String cerString = Base64.getEncoder().encodeToString(cert.getEncoded());// ����ca
//			System.out.println("cerString==" + cerString);
			// PUBLIC
//		String publicKeyString = Base64.getEncoder().encodeToString(cert.getPublicKey().getEncoded());// ���o���_
//		System.out.println("publicKeyString==" + publicKeyString);
			// PRIVATE
//			String privateKeyString = Base64.getEncoder().encodeToString(key.getEncoded());// ���o�p�_
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
