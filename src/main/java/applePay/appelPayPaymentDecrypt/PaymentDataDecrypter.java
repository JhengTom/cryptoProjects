package applePay.appelPayPaymentDecrypt;

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
	private final static byte[] iv = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00 };

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
