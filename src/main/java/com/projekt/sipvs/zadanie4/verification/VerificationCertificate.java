package com.projekt.sipvs.zadanie4.verification;

import com.projekt.sipvs.zadanie4.InvalidDocumentException;
import com.projekt.sipvs.zadanie4.Util;

import org.apache.log4j.Logger;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.bouncycastle.tsp.TimeStampToken;
import org.w3c.dom.Document;
import org.apache.log4j.Logger;
import javax.xml.xpath.XPathExpressionException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;

public class VerificationCertificate {
	
	private static final Logger logger = Logger.getLogger(VerificationEnvelope.class);
	
	public static void verifyCertificate(Document document) throws InvalidDocumentException, XPathExpressionException {

		
		
		X509CRL crl = Util.getCRL();
		TimeStampToken timeStampToken = Util.getTimestampToken(document);
		X509CertificateObject certificateObject = Util.getCertificate(document);

		try {
			certificateObject.checkValidity(timeStampToken.getTimeStampInfo().getGenTime());
		} catch (CertificateExpiredException e) {
			throw new InvalidDocumentException("The certificate was expired at the time of signing.");
		} catch (CertificateNotYetValidException e) {
			throw new InvalidDocumentException("The certificate was not yet valid at the time of signing.");
		}

		X509CRLEntry entry = crl.getRevokedCertificate(certificateObject.getSerialNumber());
			if (entry != null && timeStampToken.getTimeStampInfo().getGenTime().after(entry.getRevocationDate())) {
			throw new InvalidDocumentException("The certificate was revoked at the time of signing.");
		}
			
		
			logger.info("Certificate validity - OK");
	}

}
