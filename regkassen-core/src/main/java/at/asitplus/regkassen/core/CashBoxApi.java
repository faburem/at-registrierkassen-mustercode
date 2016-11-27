/*
 * Copyright (C) 2015, 2016
 * A-SIT Plus GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package at.asitplus.regkassen.core;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import org.jose4j.json.internal.json_simple.JSONObject;
import org.jose4j.json.internal.json_simple.JSONValue;

import static spark.Spark.*;

import org.apache.commons.lang3.StringEscapeUtils;

import at.asitplus.regkassen.common.RKSuite;
import at.asitplus.regkassen.common.util.CashBoxUtils;
import at.asitplus.regkassen.common.util.CryptoUtil;
import at.asitplus.regkassen.core.base.receiptdata.ReceiptPackage;
import at.asitplus.regkassen.core.base.receiptdata.ReceiptRepresentationForSignature;
import at.asitplus.regkassen.core.modules.DEP.DEPExportFormat;
import at.asitplus.regkassen.core.modules.init.CashBoxParameters;
import at.asitplus.regkassen.core.modules.print.ReceiptPrintType;

/**
 * Simple demonstration CashBox, can be initialized with different modules (signature, DEP, print)
 */
public class CashBoxApi {
	//parameters for cashbox initialisation (AES key, cashbox ID etc.)
	protected CashBoxParameters cashBoxParameters;

	public static void main(String[] args) {
		try{
			System.out.println("server started at " + 9000);
			port(9000);
			get("/test",(request,response) -> {
				return "bubu";
			});
			post("/encodeBelegData", (request, response) -> {
				JSONObject parameters = null;
				try {
					parameters = (JSONObject) JSONValue.parseWithException(request.body());
				} catch (Exception e1) {
					String responseText = "somethings not quite right with your JSON: " + e1.getMessage();
					// System.out.println(responseText);
					response.status(404);
					return responseText;
				}
				RKSuite rkSuite = RKSuite.R1_AT0;
				String previousReceiptJWSRepresentation = parameters.get("previousJWSRepresentation").toString();
				SimpleDateFormat df = new SimpleDateFormat( "yyyy-MM-dd'T'HH:mm:ss.SSSXXX" );
				Date receiptDate = new Date();
				if(parameters.get("receiptTime").toString() != ""){
					try {
						receiptDate = df.parse(parameters.get("receiptTime").toString());
					} catch (ParseException e) {
						// TODO Auto-generated catch block
						System.out.println(e.getMessage());
					}
				}
				CashBoxParameters cashBoxParameters = new CashBoxParameters();
				cashBoxParameters.setCashBoxId(parameters.get("cashboxID").toString());
				cashBoxParameters.setCompanyID(parameters.get("companyId").toString());
				cashBoxParameters.setTurnOverCounterAESKey(new SecretKeySpec(parameters.get("turnOverCounterAESKey").toString().getBytes(),"AES"));
				cashBoxParameters.setTurnOverCounterLengthInBytes(8);
				ReceiptRepresentationForSignature receiptRepresentationForSignature = new ReceiptRepresentationForSignature();
				receiptRepresentationForSignature.setCashBoxID(parameters.get("cashboxID").toString());
				receiptRepresentationForSignature.setReceiptIdentifier(parameters.get("receiptID").toString());
				receiptRepresentationForSignature.setReceiptDateAndTime(receiptDate);
				receiptRepresentationForSignature.setSumTaxSetNormal(Double.parseDouble(parameters.get("taxNormal").toString()));
				receiptRepresentationForSignature.setSumTaxSetErmaessigt1(Double.parseDouble(parameters.get("taxErmaessigt1").toString()));
				receiptRepresentationForSignature.setSumTaxSetErmaessigt2(Double.parseDouble(parameters.get("taxErmaessigt2").toString()));
				receiptRepresentationForSignature.setSumTaxSetNull(Double.parseDouble(parameters.get("taxNull").toString()));
				receiptRepresentationForSignature.setSumTaxSetBesonders(Double.parseDouble(parameters.get("taxBesonders").toString()));
				receiptRepresentationForSignature.setEncryptedTurnoverValue(encryptTurnOverCounter(parameters.get("cashboxID").toString(),parameters.get("receiptID").toString(),rkSuite, (long) Double.parseDouble(parameters.get("turnoverCounter").toString()),8,cashBoxParameters));
				receiptRepresentationForSignature.setSignatureCertificateSerialNumber(parameters.get("certificateID").toString());
				receiptRepresentationForSignature.setSignatureValuePreviousReceipt(calculateChainValue(cashBoxParameters, previousReceiptJWSRepresentation, rkSuite));
				// send response
				String responseText = receiptRepresentationForSignature.getDataToBeSigned(rkSuite);
				response.header("Access-Control-Allow-Origin", "*");
				response.type("text/plain");
				return responseText;
			 });
		} catch(Exception e){
			System.out.println("Exception caught: "+e);
		}
	}
	/**
	 * @return cashboxparameter set, used to setup/initialize the cashbox
	 */
	public CashBoxParameters getCashBoxParameters() {
		return cashBoxParameters;
	}

	/**
	 * export of the DEP
	 * @return DEP Export
	 */
	public DEPExportFormat exportDEP() {
		return cashBoxParameters.getDepModul().exportDEP();
	}

	/**
	 * get all receipts from DEP
	 *
	 * @return receipts stored in DEP
	 */
	public List<ReceiptPackage> getStoredReceipts() {
		return cashBoxParameters.getDepModul().getStoredReceipts();
	}

	/**
	 * print a given receipt
	 *
	 * @param receiptPackage   receipt data structure
	 * @param receiptPrintType type of printed receipt (QR-code, OCR-code)
	 * @return receipt as PDF-blob
	 */
	public byte[] printReceipt(ReceiptPackage receiptPackage, ReceiptPrintType receiptPrintType) {
		return cashBoxParameters.getPrinterModule().printReceipt(receiptPackage, receiptPrintType);
	}

	public List<byte[]> printReceipt(List<ReceiptPackage> receiptPackageList, ReceiptPrintType receiptPrintType) {
		return cashBoxParameters.getPrinterModule().printReceipt(receiptPackageList, receiptPrintType);
	}

	/**
	 * encrypt the current turnover counter
	 *
	 * @param cashBoxIDUTF8String
	 * @param receiptIdentifierUTF8String
	 * @param rkSuite
	 * @return
	 */
	protected static String encryptTurnOverCounter(String cashBoxIDUTF8String, String receiptIdentifierUTF8String, RKSuite rkSuite, long turnoverCounter, int turnOverCounterLengthInBytes, CashBoxParameters cashBoxParameters) {
		try {
			//encrypt turnover counter and store the encrypted value in the data-to-be-signed package

			//prepare IV for encryption process, the Initialisation Vector (IV) is calculating by concatenating and then
			//hashing the
			//receipt-identifier (Belegnummer) and
			//the cashbox-ID (Kassen-ID)

			//Get UTF-8 String representation of cashBox-ID (Kassen-ID), STRING in Java are already UTF-8 encoded, thus no
			//encoding transformation is done here
			//IMPORTANT HINT: NEVER EVER use the same "Kassen-ID" and "Belegnummer" for different receipts!!!!
			String IVUTF8StringRepresentation = cashBoxIDUTF8String + receiptIdentifierUTF8String;

			///hash the String with the hash-algorithm defined in the cashbox-algorithm-suite
			MessageDigest messageDigest = MessageDigest.getInstance(rkSuite.getHashAlgorithmForPreviousSignatureValue());
			byte[] hashValue = messageDigest.digest(IVUTF8StringRepresentation.getBytes());
			byte[] concatenatedHashValue = new byte[16];
			System.arraycopy(hashValue, 0, concatenatedHashValue, 0, 16);

			//encrypt the turnover counter using the AES key
			//Note: 3 AES encryption methods are provided for demonstration purposes,
			//which all use a different mode of operation (CTR, CFB, or ECB).
			//All three methods provided yield the same result. Still, they are provided here to
			//demonstrate the use of different modes of operation for encryption. This can be useful,
			//if AES functionality is re-implemented in another programming language that does
			//support selected AES modes of operation only. Please refer to
			//https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation for more details
			//on different modes of operation for block ciphers
			String base64EncryptedTurnOverValue1 = null;

			base64EncryptedTurnOverValue1 = CryptoUtil.encryptCTR(concatenatedHashValue, turnoverCounter, cashBoxParameters.getTurnOverCounterAESKey(),turnOverCounterLengthInBytes);

			String base64EncryptedTurnOverValue2 = CryptoUtil.encryptCFB(concatenatedHashValue, turnoverCounter, cashBoxParameters.getTurnOverCounterAESKey(),turnOverCounterLengthInBytes);
			String base64EncryptedTurnOverValue3 = CryptoUtil.encryptECB(concatenatedHashValue, turnoverCounter, cashBoxParameters.getTurnOverCounterAESKey(),turnOverCounterLengthInBytes);
			if (!base64EncryptedTurnOverValue1.equals(base64EncryptedTurnOverValue2)) {
				System.out.println("ENCRYPTION ERROR IN METHOD updateTurnOverCounter, MUST NOT HAPPEN");
				System.exit(-1);
			}
			if (!base64EncryptedTurnOverValue1.equals(base64EncryptedTurnOverValue3)) {
				System.out.println("ENCRYPTION ERROR IN METHOD updateTurnOverCounter, MUST NOT HAPPEN");
				System.exit(-1);
			}


			//THE FOLLOWING CODE IS ONLY FOR DEMONSTRATION PURPOSES
			//decryption and reconstruction of the turnover value
			//this is just here for demonstration purposes (so that the whole encryption/decryption process can be found in one place)
			//and not needed for that function
			//IV needs to be setup the same way as above
			//encryptedTurnOverValue needs to be reconstructed as described in the used utility method
			//Note: 3 AES decryption methods are provided for demonstration purposes,
			//which all use a different mode of operation (CTR, CFB, or ECB).
			//All three methods provided yield the same result. Still, they are provided here to
			//demonstrate the use of different modes of operation for decryption. This can be useful, if
			//AES functionality is re-implemented in another programming language that does
			//support selected AES modes of operation only. Please refer to
			//https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation for more details
			//on different modes of operation for block ciphers
			long testPlainOverTurnOverReconstructed1 = CryptoUtil.decryptCTR(concatenatedHashValue, base64EncryptedTurnOverValue1, cashBoxParameters.getTurnOverCounterAESKey());
			long testPlainOverTurnOverReconstructed2 = CryptoUtil.decryptCFB(concatenatedHashValue, base64EncryptedTurnOverValue2, cashBoxParameters.getTurnOverCounterAESKey());
			long testPlainOverTurnOverReconstructed3 = CryptoUtil.decryptECB(concatenatedHashValue, base64EncryptedTurnOverValue3, cashBoxParameters.getTurnOverCounterAESKey());
			if (testPlainOverTurnOverReconstructed1 != testPlainOverTurnOverReconstructed2) {
				System.out.println("DECRYPTION ERROR IN METHOD updateTurnOverCounter, MUST NOT HAPPEN");
				System.exit(-1);
			}

			if (testPlainOverTurnOverReconstructed1 != testPlainOverTurnOverReconstructed3) {
				System.out.println("DECRYPTION ERROR IN METHOD updateTurnOverCounter, MUST NOT HAPPEN");
				System.exit(-1);
			}

			if (turnoverCounter != testPlainOverTurnOverReconstructed1) {
				System.out.println("DECRYPTION ERROR IN METHOD updateTurnOverCounter, MUST NOT HAPPEN");
				System.exit(-1);
			}

			return base64EncryptedTurnOverValue1;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * calculate cryptographic chain value
	 *
	 * @param previousReceiptJWSRepresentation previous receipt for chain value calculation, if null, the cashboxID is used
	 * @param rkSuite                          rksuite that contains information of the to-be-used HASH-algorithm
	 * @return
	 */
	protected static String calculateChainValue(CashBoxParameters cashBoxParameters, String previousReceiptJWSRepresentation, RKSuite rkSuite) {
		try {
			String inputForChainCalculation;

			//Detailspezifikation Abs 4 "Sig-Voriger-Beleg"
			//if the first receipt is stored, then the cashbox-identifier is hashed and is used as chaining value
			//otherwise the complete last receipt is hased and the result is used as chaining value
			if (previousReceiptJWSRepresentation == null) {
				inputForChainCalculation = cashBoxParameters.getCashBoxId();
			} else {
				inputForChainCalculation = previousReceiptJWSRepresentation;
			}

			//set hash algorithm from RK suite, in this case SHA-256
			MessageDigest md = MessageDigest.getInstance(rkSuite.getHashAlgorithmForPreviousSignatureValue());

			//calculate hash value
			md.update(inputForChainCalculation.getBytes());
			byte[] digest = md.digest();

			//extract number of bytes (N, defined in RKsuite) from hash value
			int bytesToExtract = rkSuite.getNumberOfBytesExtractedFromPrevSigHash();
			byte[] conDigest = new byte[bytesToExtract];
			System.arraycopy(digest, 0, conDigest, 0, bytesToExtract);

			//encode value as BASE64 String ==> chainValue
			return CashBoxUtils.base64Encode(conDigest, false);

		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return null;
	}
}
