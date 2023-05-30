package applePay.appelPayPaymentDecrypt;

/*
 * https://developer.apple.com/library/archive/documentation/PassKit/Reference/PaymentTokenJSON/PaymentTokenJSON.html#//apple_ref/doc/uid/TP40014929
 * header����
 * */
public class ApplePayPaymentToken {

	public Token token;

	public Token getToken() {
		return token;
	}

	public static class Token {

		public PaymentData paymentData;

		public PaymentMethod paymentMethod;

		public String transactionIdentifier;

		public PaymentData getPaymentData() {
			return paymentData;
		}

		public PaymentMethod getPaymentMethod() {
			return paymentMethod;
		}

		public String getTransactionIdentifier() {
			return transactionIdentifier;
		}

		public static class PaymentData {
			String data;
			String signature;
			String version;
			Header header;

			public String getData() {
				return data;
			}

			public String getSignature() {
				return signature;
			}

			public String getVersion() {
				return version;
			}

			public Header getHeader() {
				return header;
			}

			public static class Header {
				@Override
				public String toString() {
					return "Header [publicKeyHash=" + publicKeyHash + ", ephemeralPublicKey=" + ephemeralPublicKey
							+ ", transactionId=" + transactionId + "]";
				}

				String applicationData;
				String publicKeyHash;
				String ephemeralPublicKey;
				String transactionId;

				public String getApplicationData() {
					return applicationData;
				}

				public void setApplicationData(String applicationData) {
					this.applicationData = applicationData;
				}

				public String getPublicKeyHash() {
					return publicKeyHash;
				}

				public String getEphemeralPublicKey() {
					return ephemeralPublicKey;
				}

				public String getTransactionId() {
					return transactionId;
				}

			}
		}

		public static class PaymentMethod {
			String displayName;
			String network;
			String type;

			public String getDisplayName() {
				return displayName;
			}

			public String getNetwork() {
				return network;
			}

			public String getType() {
				return type;
			}

		}
	}
}