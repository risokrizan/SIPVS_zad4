package com.projekt.sipvs.zadanie4.verification;

import org.w3c.dom.Document;


import com.projekt.sipvs.zadanie4.InvalidDocumentException;
import com.projekt.sipvs.zadanie4.Util;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Base64;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.X509CRL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import org.apache.log4j.Logger;
import javax.xml.xpath.XPathException;
import it.svario.xpathapi.jaxp.XPathAPI;
import org.w3c.dom.Node;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.tsp.TimeStampToken;


public class VerificationTimestamp {
	private static final Logger logger = Logger.getLogger(VerificationEnvelope.class);
	
	public static void verifyTimestamp(Document document) throws InvalidDocumentException{
		
		
		X509CRL crl = Util.getCRL();
		TimeStampToken token = Util.getTimestampToken(document);
		
		verifyTimestampCerfificate(crl, token);
		
		verifyMessageImprint(token, document);
		logger.info("References ds:Manifest - OK");
	}
	
	
	
	public static void verifyTimestampCerfificate(X509CRL crl, TimeStampToken ts_token) throws InvalidDocumentException {
		X509CertificateHolder signer = null;

		Store<X509CertificateHolder> certHolders = ts_token.getCertificates();
		ArrayList<X509CertificateHolder> certList = new ArrayList<>(certHolders.getMatches(null));

		BigInteger serialNumToken = ts_token.getSID().getSerialNumber();
		X500Name issuerToken = ts_token.getSID().getIssuer();

		for (X509CertificateHolder certHolder : certList) {
			if (certHolder.getSerialNumber().equals(serialNumToken) && certHolder.getIssuer().equals(issuerToken)){
				signer = certHolder;
				break;
			}
		}

		if (signer == null){
			throw new InvalidDocumentException("Signed certificate of TS is not found in document.");
		}

		if (!signer.isValidOn(new Date())){
			throw new InvalidDocumentException("Signed certificate of TS is not valid compared to current time.");
		}
		
		logger.info("TS compared to UTC NOW - OK");
		

		if (crl.getRevokedCertificate(signer.getSerialNumber()) != null){
			throw new InvalidDocumentException("Signed certificate of TS is not valid compared to last valid CRL.");
		}
		
		logger.info("TS compared to last valid CRL - OK");

	}
	
	
	public static void verifyMessageImprint(TimeStampToken ts_token, Document document) throws InvalidDocumentException {
		byte[] messageImprint = ts_token.getTimeStampInfo().getMessageImprintDigest();
		String hashAlg = ts_token.getTimeStampInfo().getHashAlgorithm().getAlgorithm().getId();

		Map<String, String> nsMap = new HashMap<>();
		nsMap.put("ds", "http://www.w3.org/2000/09/xmldsig#");

		Node signatureValueNode = null;

		try {
			signatureValueNode = XPathAPI.selectSingleNode(document, "//ds:Signature/ds:SignatureValue", nsMap);
		} catch (XPathException e) {
			e.printStackTrace();
		}

		if (signatureValueNode == null){
			throw new InvalidDocumentException("Element ds:SignatureValue not found.");
		}

		byte[] signatureValue = Base64.decode(signatureValueNode.getTextContent().getBytes());

		MessageDigest messageDigest = null;
		try {
			messageDigest = MessageDigest.getInstance(hashAlg, "BC");
		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			throw new InvalidDocumentException("Not supported algorithm in message digest.");
		}

		if (!Arrays.equals(messageImprint, messageDigest.digest(signatureValue))){
			throw new InvalidDocumentException("MessageImprint from TS and signature ds:SignatureValue does not match.");
		}
		
		logger.info("MessageImprint from TS compared to ds:SignatureValue - OK");

	}
}
