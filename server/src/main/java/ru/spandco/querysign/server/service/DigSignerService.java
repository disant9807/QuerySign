package ru.spandco.querysign.server.service;

import com.objsys.asn1j.runtime.Asn1BerDecodeBuffer;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureException;
import org.apache.xml.security.transforms.InvalidTransformException;
import org.apache.xml.security.transforms.Transform;
import org.apache.xml.security.exceptions.AlgorithmAlreadyRegisteredException;
import org.apache.xml.security.transforms.TransformationException;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.transforms.params.XPath2FilterContainer;
import org.apache.xml.security.utils.XMLUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.boot.context.event.ApplicationStartedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.ContentInfo;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.SignedData;
import ru.CryptoPro.JCP.Digest.GostDigest;
import ru.CryptoPro.JCP.tools.AlgorithmUtility;
import ru.spandco.binarystoragemodel.*;
import ru.spandco.binstorageproxy.BinaryProxy;
import ru.spandco.querysign.server.CMS.CMS;
import ru.spandco.querysign.server.SPI.SmevTransformSpi;

import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.*;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

@Service("DigSignerService")

public class DigSignerService {

    @Autowired
    private BinaryProxy binaryProxy;

    @Autowired
    private CertificateStoreService certificateStoreService;

    private static Logger logger = LoggerFactory.getLogger(DigSignerService.class);
    private static final String XMLDSIG_MORE_GOSTR34102001_GOSTR3411 = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256";
    private static final String XMLDSIG_MORE_GOSTR3411 = "http://www.w3.org/2001/04/xmldsig-more#gostr3411";
    private static final String CANONICALIZATION_METHOD = "http://www.w3.org/2001/10/xml-exc-c14n#";
    private static final String DS_SIGNATURE = "//ds:Signature";
    private static final String SIG_ID = "sigID";
    private static final String COULD_NOT_FIND_XML_ELEMENT_NAME = "ERROR! Could not find xmlElementName = ";
    private static final String GRID = "#";
    private static final String XML_SIGNATURE_ERROR = "xmlDSignature ERROR: ";
    private static final String IGNORE_LINE_BREAKS_FIELD = "ignoreLineBreaks";
    private static final QName QNAME_SIGNATURE = new QName("http://www.w3.org/2000/09/xmldsig#", "Signature", "ds");
    private static final String SIGNATURE_NOT_FOUND = "Signature not found!";
    private static final String SIGNATURE_NOT_VALID = "Signature not valid";
    private static final String SMEV_SIGNATURE_PASSED_CORE_VALIDATION = "SmevSignature passed core validation";
    private static final String VERIFY_SIGNATURE_ON_XML_IO_EXCEPTION = "Verify signature on XML IOException: ";
    private static final String VERIFY_SIGNATURE_ON_XML_PARSER_CONFIGURATION_EXCEPTION = "Verify signature on XML ParserConfigurationException: ";
    private static final String VERIFY_SIGNATURE_ON_XML_SAX_EXCEPTION = "Verify signature on XML SAXException: ";
    private static final String VERIFY_SIGNATURE_ON_XML_XML_SIGNATURE_EXCEPTION = "Verify signature on XML XMLSignatureException: ";
    private static final String VERIFY_SIGNATURE_ON_XML_XML_SECURITY_EXCEPTION = "Verify signature on XML XMLSecurityException: ";
    private static final String ID = "Id";

    public static final String XmlDsigNamespaceUrl = "http://www.w3.org/2000/09/xmldsig#";

    @EventListener(ApplicationReadyEvent.class)
    public void runAfterStartup() {
        ru.CryptoPro.JCPxml.xmldsig.JCPXMLDSigInit.init();

        try {
            Transform.register(SmevTransformSpi.ALGORITHM_URN, SmevTransformSpi.class.getName());
            santuarioIgnoreLineBreaks(true);
            logger.info("SmevTransformSpi has been initialized");
        } catch (AlgorithmAlreadyRegisteredException | ClassNotFoundException | InvalidTransformException e) {
            logger.error("SmevTransformSpi Algorithm already registered: " + e.getMessage());
        }

        System.setProperty("org.apache.xml.security.ignoreLineBreaks", "true");
    }

    private void santuarioIgnoreLineBreaks(Boolean mode) {
        try {
            Boolean currMode = mode;
            AccessController.doPrivileged(new PrivilegedExceptionAction<Boolean>() {

                public Boolean run() throws Exception {
                    Field f = XMLUtils.class.getDeclaredField(IGNORE_LINE_BREAKS_FIELD);
                    f.setAccessible(true);
                    f.set(null, currMode);
                    return false;
                }
            });

        } catch (Exception e) {
            logger.error("santuarioIgnoreLineBreaks " + e.getMessage());
        }
    }

    public String CreateXmlSignature(String xmlToSign, String nodeId,
                                     String certId, Boolean signatureOnly)
            throws CertificateException, IOException, KeyStoreException,
            NoSuchAlgorithmException, NoSuchProviderException, ParserConfigurationException, UnrecoverableKeyException {

        Map.Entry<X509Certificate, PrivateKey> certEntry = certificateStoreService
                .GetCertificate(null, null, null);

        PrivateKey privateKey = certEntry.getValue();
        X509Certificate publicCertificate = certEntry.getKey();


        try {
            byte[] signingDoc = SignatureDoc(xmlToSign.getBytes(),
                    "CallerInformationSystemSignature",
                    nodeId,
                    publicCertificate,
                    privateKey);

            if (!ValidateSignature(signingDoc)) {
                throw new SignatureException("Ошибка");
            }
            return new String(signingDoc, StandardCharsets.UTF_8);

        } catch (Exception e) {
            logger.error(e.getMessage());
        }
        return xmlToSign;
    }

    private byte[] SignatureDoc(byte[] data, String xmlElementName,
                                String xmlElementID,
                                X509Certificate certificate,
                                PrivateKey privateKey) {
        ByteArrayOutputStream bais;
        try {
            // инициализация объекта чтения XML-документа
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();

            // установка флага, определяющего игнорирование пробелов в
            // содержимом элементов при обработке XML-документа
            dbf.setIgnoringElementContentWhitespace(true);

            // установка флага, определяющего преобразование узлов CDATA в
            // текстовые узлы при обработке XML-документа
            dbf.setCoalescing(true);

            // установка флага, определяющего поддержку пространств имен при
            // обработке XML-документа
            dbf.setNamespaceAware(true);

            // загрузка содержимого подписываемого документа на основе
            // установленных флагами правил из массива байтов data

            DocumentBuilder documentBuilder = dbf.newDocumentBuilder();
            Document doc = documentBuilder.parse(new ByteArrayInputStream(data));

            /*
             * Добавление узла подписи <ds:Signature> в загруженный XML-документ
             */

            // алгоритм подписи (ГОСТ Р 34.10-2001)
            final String signMethod = XMLDSIG_MORE_GOSTR34102001_GOSTR3411;

            // алгоритм хеширования, используемый при подписи (ГОСТ Р 34.11-94)
            final String digestMethod = XMLDSIG_MORE_GOSTR3411;

            final String canonicalizationMethod = CANONICALIZATION_METHOD;


            String[][] filters = {{XPath2FilterContainer.SUBTRACT, DS_SIGNATURE}};
            String sigId = SIG_ID;

            // инициализация объекта формирования ЭЦП в соответствии с
            // алгоритмом ГОСТ Р 34.10-2001
            XMLSignature sig = new XMLSignature(doc, "", signMethod, canonicalizationMethod);

            // определение идентификатора первого узла подписи

            sig.setId(sigId);

            // получение корневого узла XML-документа
            Element anElement = null;
            if (xmlElementName == null) {
                anElement = doc.getDocumentElement();
            } else {
                NodeList nodeList = doc.getElementsByTagName(xmlElementName);
                anElement = (Element) nodeList.item(0);
            }

            // добавление в корневой узел XML-документа узла подписи
            if (anElement != null) {
                anElement.appendChild(sig.getElement());
            } else {
                throw new RuntimeException(COULD_NOT_FIND_XML_ELEMENT_NAME + xmlElementName);
            }

            /*
             * Определение правил работы с XML-документом и добавление в узел подписи этих
             * правил
             */

            // создание узла преобразований <ds:Transforms> обрабатываемого
            // XML-документа
            Transforms transforms = new Transforms(doc);

            // добавление в узел преобразований правил работы с документом
            // transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
            transforms.addTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
            transforms.addTransform(SmevTransformSpi.ALGORITHM_URN);

            // добавление в узел подписи ссылок (узла <ds:Reference>),
            // определяющих правила работы с
            // XML-документом (обрабатывается текущий документ с заданными в
            // узле <ds:Transforms> правилами
            // и заданным алгоритмом хеширования)
            sig.addDocument(xmlElementID == null ? "" : GRID + xmlElementID, transforms, digestMethod);

            /*
             * Создание подписи всего содержимого XML-документа на основе закрытого ключа,
             * заданных правил и алгоритмов
             */

            // создание внутри узла подписи узла <ds:KeyInfo> информации об
            // открытом ключе на основе
            // сертификата
            sig.addKeyInfo(certificate);

            // создание подписи XML-документа
            sig.sign(privateKey);

            // определение потока, в который осуществляется запись подписанного
            // XML-документа
            bais = new ByteArrayOutputStream();

            // инициализация объекта копирования содержимого XML-документа в
            // поток
            TransformerFactory tf = TransformerFactory.newInstance();

            // создание объекта копирования содержимого XML-документа в поток
            Transformer trans = tf.newTransformer();

            // копирование содержимого XML-документа в поток
            trans.transform(new DOMSource(doc), new StreamResult(bais));
            bais.close();
        } catch (TransformationException e) {
            throw new RuntimeException("TransformationException " + XML_SIGNATURE_ERROR + e.getMessage());
        } catch (XMLSignatureException e) {
            throw new RuntimeException("XMLSignatureException " + XML_SIGNATURE_ERROR + e.getMessage());
        } catch (TransformerException e) {
            throw new RuntimeException("TransformerException " + XML_SIGNATURE_ERROR + e.getMessage());
        } catch (IOException e) {
            throw new RuntimeException("IOException " + XML_SIGNATURE_ERROR + e.getMessage());
        } catch (XMLSecurityException e) {
            throw new RuntimeException("XMLSecurityException " + XML_SIGNATURE_ERROR + e.getMessage());
        } catch (ParserConfigurationException e) {
            throw new RuntimeException(
                    "ParserConfigurationException " + XML_SIGNATURE_ERROR + e.getMessage());
        } catch (SAXException e) {
            throw new RuntimeException(e);
        }
            return bais.toByteArray();
    }

    private boolean ValidateSignature(byte[] signedXmlData) {
        boolean coreValidity = true;
        try {
            DocumentBuilderFactory bf = DocumentBuilderFactory.newInstance();
            bf.setNamespaceAware(true);
            DocumentBuilder b = bf.newDocumentBuilder();
            Document doc = b.parse(new InputSource(new ByteArrayInputStream(signedXmlData)));

            NodeList sigs = doc.getElementsByTagNameNS(QNAME_SIGNATURE.getNamespaceURI(), QNAME_SIGNATURE.getLocalPart());
            org.apache.xml.security.signature.XMLSignature sig = null;
            sigSearch: {
                for (int i = 0; i < sigs.getLength(); i++) {
                    Element sigElement = (Element) sigs.item(i);
                    String sigId = sigElement.getAttribute(ID);
                    if (sigId != null) {
                        sig = new org.apache.xml.security.signature.XMLSignature(sigElement, "");
                        break sigSearch;
                    }
                }
                throw new RuntimeException(SIGNATURE_NOT_FOUND);
                //throw new XMLSignatureVerificationException(SIGNATURE_NOT_FOUND);
            }
            org.apache.xml.security.keys.KeyInfo ki = (org.apache.xml.security.keys.KeyInfo) sig.getKeyInfo();

            X509Certificate certificate = ki.getX509Certificate();

            if (!sig.checkSignatureValue(certificate.getPublicKey())) {
                coreValidity = false;
                logger.info(SIGNATURE_NOT_VALID);
            } else {
                logger.info(String.format(SMEV_SIGNATURE_PASSED_CORE_VALIDATION));
            }

        } catch (IOException e) {
            throw new RuntimeException(VERIFY_SIGNATURE_ON_XML_IO_EXCEPTION + e.getMessage());
            //throw new XMLSignatureVerificationException(VERIFY_SIGNATURE_ON_XML_IO_EXCEPTION + ExceptionUtils.getStackTrace(e));
        } catch (ParserConfigurationException e) {
            throw new RuntimeException(VERIFY_SIGNATURE_ON_XML_PARSER_CONFIGURATION_EXCEPTION + e.getMessage());
            //throw new XMLSignatureVerificationException(VERIFY_SIGNATURE_ON_XML_PARSER_CONFIGURATION_EXCEPTION + ExceptionUtils.getStackTrace(e));
        } catch (SAXException e) {
            throw new RuntimeException(VERIFY_SIGNATURE_ON_XML_SAX_EXCEPTION + e.getMessage());
            //throw new XMLSignatureVerificationException(VERIFY_SIGNATURE_ON_XML_SAX_EXCEPTION + ExceptionUtils.getStackTrace(e));
        } catch (org.apache.xml.security.signature.XMLSignatureException e) {
            throw new RuntimeException(VERIFY_SIGNATURE_ON_XML_XML_SIGNATURE_EXCEPTION + e.getMessage());
            //throw new XMLSignatureVerificationException(VERIFY_SIGNATURE_ON_XML_XML_SIGNATURE_EXCEPTION + ExceptionUtils.getStackTrace(e));
        } catch (XMLSecurityException e) {
            throw new RuntimeException(VERIFY_SIGNATURE_ON_XML_XML_SECURITY_EXCEPTION + e.getMessage());
            //throw new XMLSignatureVerificationException(VERIFY_SIGNATURE_ON_XML_XML_SECURITY_EXCEPTION + ExceptionUtils.getStackTrace(e));
        }

        return coreValidity;
    }

    private byte[] CreatePkcs7Signature(boolean detached, String binStorageId, String certId) throws Exception {
        byte[] signingData = GetDataFromBinaryStorage(binStorageId);
        return CreatePkcs7Signature(detached, signingData, certId);
    }

    private byte[] CreatePkcs7Signature(boolean detached, byte[] dataToSign, String certId)
            throws Exception {
        Map.Entry<X509Certificate, PrivateKey> certEntry = certificateStoreService
                .GetCertificate(null, null, null);

        PrivateKey privateKey = certEntry.getValue();
        X509Certificate publicCertificate = certEntry.getKey();


        final Signature signature = Signature.getInstance("GOST3411_2012_256withGOST3410_2012_256");
        signature.initSign(privateKey);

        byte[] result = CMS.createCMS(dataToSign, signature.sign(), publicCertificate, detached);
        return result;
    }

    public byte[] CreateDetachedSignature(String binDataId, String certId) throws Exception {
        return CreatePkcs7Signature(true, binDataId, certId);
    }

    public byte[] CreateAttachedSignature (String binDataId, String certId) throws Exception {
        return CreatePkcs7Signature(false, binDataId, certId);
    }

    public byte[] CreateHash (String binDataId) throws NoSuchAlgorithmException, IOException {
        byte[] signingData =  GetDataFromBinaryStorage(binDataId);
        MessageDigest messageDigest = new GostDigest();
        return messageDigest.digest(signingData);
    }


    public boolean ValidateXmlSignature (String validatingXml) throws ParserConfigurationException, IOException, SAXException, XMLSecurityException, CertificateException {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        DocumentBuilder documentBuilder = dbf.newDocumentBuilder();
        Document doc = documentBuilder.parse(new InputSource(new StringReader(validatingXml)));

        NodeList nodeList = doc.getElementsByTagNameNS(XmlDsigNamespaceUrl, "Signature");

        List<Boolean> resultList = new ArrayList();
        for(int curSign = 0; curSign < nodeList.getLength(); curSign++ ) {

            final String signMethod = XMLDSIG_MORE_GOSTR34102001_GOSTR3411;

            // алгоритм хеширования, используемый при подписи (ГОСТ Р 34.11-94)
            final String digestMethod = XMLDSIG_MORE_GOSTR3411;

            final String canonicalizationMethod = CANONICALIZATION_METHOD;

            Document signedXml = nodeList.item(curSign).getOwnerDocument();

            // инициализация объекта формирования ЭЦП в соответствии с
            // алгоритмом ГОСТ Р 34.10-2001
            XMLSignature sig = new XMLSignature(signedXml, "", signMethod, canonicalizationMethod);

            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            InputStream in = new ByteArrayInputStream(sig.getSignatureValue());
            X509Certificate cert = (X509Certificate)certFactory.generateCertificate(in);
            PublicKey pk = cert.getPublicKey();

            resultList.add(sig.checkSignatureValue(pk));
        }

        return resultList.stream()
                .filter(z -> z)
                .count() == nodeList.getLength();
    }

    public boolean ValidateSignaturePKCS7File (String sigBinDataId, String cntBinDataId) {
        try {
            byte[] signingData = GetDataFromBinaryStorage(cntBinDataId);
            byte[] sig = GetDataFromBinaryStorage(sigBinDataId);

            Asn1BerDecodeBuffer asnCont = new Asn1BerDecodeBuffer(signingData);
            ContentInfo cntInfo = new ContentInfo();
            cntInfo.decode(asnCont);

            SignedData signData = (SignedData)cntInfo.content;

            Asn1BerDecodeBuffer AsnSig = new Asn1BerDecodeBuffer(sig);
            signData.decode(AsnSig);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public boolean ValidateSignaturePKCS7File (String binDataId) {
        try {
            byte[] cnt = GetDataFromBinaryStorage(binDataId);

            SignedData signData = new SignedData();
            Asn1BerDecodeBuffer AsnCnt = new Asn1BerDecodeBuffer(cnt);
            signData.decode(AsnCnt);

            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private byte[] GetDataFromBinaryStorage(String binStorageId) throws IOException {
        BinaryModel data = binaryProxy.Get(binStorageId);
        return data.Content.toByteArray();
    }
}
