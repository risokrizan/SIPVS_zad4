package com.projekt.sipvs.zadanie4.verification;

import org.apache.log4j.Logger;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import com.projekt.sipvs.zadanie4.InvalidDocumentException;
import com.projekt.sipvs.zadanie4.Util;

public class VerificationEnvelope {
	private static final Logger logger = Logger.getLogger(VerificationEnvelope.class);

	public static void verifyEnvelope(Document document) throws InvalidDocumentException{
		Element root = document.getDocumentElement();
		

		if (!Util.checkAttributeValue(root, "xmlns:xzep", "http://www.ditec.sk/ep/signature_formats/xades_zep/v1.0")) {
			throw new InvalidDocumentException(
					"Root element must have attribute xmlns:xzep with value set=http://www.ditec.sk/ep/signature_formats/xades_zep/v1.0");
		}
		
		logger.info("xmlns:xzep - OK");
		
		if (!Util.checkAttributeValue(root, "xmlns:ds", "http://www.w3.org/2000/09/xmldsig#")) {
			throw new InvalidDocumentException(
					"Root element must have attribute xmlns:ds with value set=http://www.w3.org/2000/09/xmldsig#");
		}
		
		logger.info("xmlns:ds - OK");
	}
	
}
