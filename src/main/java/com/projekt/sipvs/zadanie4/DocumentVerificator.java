package com.projekt.sipvs.zadanie4;

import java.io.File;
import java.io.IOException;
import java.io.StringReader;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.List;

import org.apache.log4j.Logger;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPathExpressionException;

import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.Text;
import org.xml.sax.InputSource;


import com.projekt.sipvs.zadanie4.verification.VerificationCertificate;
import com.projekt.sipvs.zadanie4.verification.VerificationEnvelope;
import com.projekt.sipvs.zadanie4.verification.VerificationTimestamp;
import com.projekt.sipvs.zadanie4.verification.VerificationXMLSignature;


public class DocumentVerificator {
	
	private static final Logger logger = Logger.getLogger(DocumentVerificator.class);
	private static final String XML_HEADER = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>";
	private static final String UTF8_BOM = "\uFEFF";
	
	private File[] documents = null;

	
	public DocumentVerificator() {
		String userDir = System.getProperty("user.dir");
		File workingDirectory = new File(userDir + "\\src\\main\\resource\\documents");
		
		documents= workingDirectory.listFiles();
	}
	
	public void verifyDocuments() {

        for (File f : documents) {
            System.out.println(f.getName());
            
            String documentContent = null;
			try {
				documentContent = readFile(f.getPath());
				documentContent = removeUTF8BOM(documentContent);
				documentContent = addXMLHeader(documentContent);
	
			} catch (IOException e) {
				logger.error("Cannot open or read " + f.getPath(), e);
				continue;
			}
            
           
            Document document = null;
            
			try {
				document = convertToDocument(documentContent);
				
			} catch (Exception e) {
				logger.error("Cannot parse " + f.getPath() + " content into org.w3c.dom.Document", e);
				continue;
			}
            
            try {
				verify(document);
				logger.info("Document " + f.getName() + " is XADES-T valid!\n");
				
			} catch (InvalidDocumentException | XPathExpressionException e) {
				logger.error("Document " + f.getName() + " is not XADES-T valid!\n" + e.getMessage()+ "\n");
			}
            
            
        }
		
	}
	
	public void verify(Document document) throws InvalidDocumentException, XPathExpressionException {
		VerificationEnvelope.verifyEnvelope(document);
		VerificationXMLSignature.verifyXMLSignature(document);
		VerificationTimestamp.verifyTimestamp(document);
		VerificationCertificate.verifyCertificate(document);
		
	}
		
	
	private String readFile(String filePath) throws IOException {
		
		byte[] encoded = Files.readAllBytes(Paths.get(filePath));
		return new String(encoded, Charset.defaultCharset());
	}
	
	private String removeUTF8BOM(String s) {
	
		if (s.startsWith(UTF8_BOM)) {
	        s = s.substring(1);
	    }
	    return s;
	}
	
	//Ukazky XML dokumentov nemaju prvy xml tag v documente
	private String addXMLHeader(String s) {
		
		if (s.startsWith("<?xml") == false) {	
			s = XML_HEADER + s;
		}
		return s;
	}
	
	
	private Document convertToDocument(String s) throws Exception {
		
		DocumentBuilderFactory documentFactory = DocumentBuilderFactory.newInstance();
		documentFactory.setNamespaceAware(true);
		DocumentBuilder documentBuilder = documentFactory.newDocumentBuilder();
		InputSource source = new InputSource(new StringReader(s));
		
		return documentBuilder.parse(source);
	}
	
	

}
