package ru.spandco.querysign.querysignproxy;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.ls.DOMImplementationLS;
import org.w3c.dom.ls.LSSerializer;
import org.xml.sax.SAXException;
import ru.spandco.binarystoragemodel.ApiHeaders;
import ru.spandco.binarystoragemodel.BinaryModel;
import ru.spandco.binarystoragemodel.SaveMode;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

@Service("BinaryProxy")
@RequiredArgsConstructor
public class QueryProxy {
    private String serviceUrl = "http://localhost:8002/sign";
    private String xmlSigUrl = "/xml";
    private String detach = "/det";
    private String hash = "/hash";


    @Autowired
    private RestTemplate rest;

    public Element CreateSignature(Element dataToSign, String nodeId) throws ParserConfigurationException, IOException, SAXException {
        if (nodeId == null || nodeId.isEmpty()) {
            throw new IllegalArgumentException();
        }
        if (dataToSign == null) {
            throw new IllegalArgumentException();
        }

        Document document = dataToSign.getOwnerDocument();
        DOMImplementationLS domImplLS = (DOMImplementationLS) document
                .getImplementation();
        LSSerializer serializer = domImplLS.createLSSerializer();
        String strDataToSign = serializer.writeToString(dataToSign);


        MultiValueMap<String, Object> body = new LinkedMultiValueMap<String, Object>();
        body.add("source", strDataToSign);
        HttpEntity<?> request = new HttpEntity<>(
                body, new HttpHeaders()
        );


        ResponseEntity<String> response = rest
                .exchange(serviceUrl + xmlSigUrl + "?nodeId=" + nodeId, HttpMethod.POST, request, String.class);

        if (!response.getStatusCode().is2xxSuccessful()) {
            throw new IllegalArgumentException();
        }

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
        Document doc = documentBuilder.parse(new ByteArrayInputStream(response.getBody().getBytes()));

        return doc.getDocumentElement();
    }

    public byte[] GetDetachedSignature(String dataId) {
        if (dataId == null) {
            throw new IllegalArgumentException();
        }

        HttpEntity request = new HttpEntity(new HttpHeaders());

        ResponseEntity<byte[]> response = rest
                .exchange(serviceUrl + detach + "?id=" + dataId, HttpMethod.GET, request, byte[].class);

        if (!response.getStatusCode().is2xxSuccessful()) {
            throw new IllegalArgumentException();
        }

        return response.getBody();
    }

    public byte[] GetGostHash(String dataId) {
        if (dataId == null) {
            throw new IllegalArgumentException();
        }

        HttpEntity request = new HttpEntity(new HttpHeaders());

        ResponseEntity<byte[]> response = rest
                .exchange(serviceUrl + hash + "?id=" + dataId, HttpMethod.GET, request, byte[].class);

        if (!response.getStatusCode().is2xxSuccessful()) {
            throw new IllegalArgumentException();
        }

        return response.getBody();
    }



    private static void ValidateSuccessStatusCode(HttpStatus status) throws FileNotFoundException {
        if (!status.is2xxSuccessful()) {
            if (status == HttpStatus.NOT_FOUND) {
                throw new FileNotFoundException();
            }
            else if (status == HttpStatus.BAD_REQUEST) {
                throw new IllegalArgumentException();
            }
        }
    }
}
