package ru.spandco.querysign.server.controllers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.lang.Nullable;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import ru.spandco.binarystoragemodel.SaveMode;
import ru.spandco.binarystoragemodel.BinaryModel;
import ru.spandco.querysign.server.service.DigSignerService;

import java.io.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@RequestMapping("/sign")
@RestController
public class DigSignController {

    private final Logger logger =
            LoggerFactory.getLogger(DigSignController.class);

    private DigSignerService digSignerService;

    @Autowired
    public void setService(DigSignerService dependency) {
        digSignerService = dependency;
    }

    @RequestMapping(
            path = "/det",
            method = RequestMethod.GET)
    public HttpEntity<?> GetDetachedSig (@RequestParam String id,
                                            @RequestParam String certId) throws Exception {
        try {
            byte[] detachedSig = digSignerService.CreateDetachedSignature(id, certId);

            HttpHeaders headers = new HttpHeaders();
            headers.add("Content-Type", "application/octet-stream");

            ContentDisposition contentDisposition = ContentDisposition
                    .builder("attachment")
                    .filename(certId)
                    .build();
            headers.setContentDisposition(contentDisposition);

            return new HttpEntity<>(detachedSig, headers);
        }
        catch (Exception e) {
            logger.error("Проблема создания отсоединенной подписи по id " + certId +
                    " из-за ошибки: " + e.getMessage());
            return new ResponseEntity<>(e.getMessage(),
                    HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @RequestMapping(
            path = "/att",
            method = RequestMethod.GET)
    public HttpEntity<?> GetAttachedSig (@RequestParam String id,
                                         @RequestParam String certId) throws Exception {
        try {
            byte[] detachedSig = digSignerService.CreateAttachedSignature(id, certId);

            HttpHeaders headers = new HttpHeaders();
            headers.add("Content-Type", "application/octet-stream");

            ContentDisposition contentDisposition = ContentDisposition
                    .builder("attachment")
                    .filename(certId)
                    .build();
            headers.setContentDisposition(contentDisposition);

            return new HttpEntity<>(detachedSig, headers);
        }
        catch (Exception e) {
            logger.error("Проблема создания подписи по id " + certId +
                    " из-за ошибки: " + e.getMessage());
            return new ResponseEntity<>(e.getMessage(),
                    HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @RequestMapping(
            path = "/hash",
            method = RequestMethod.GET)
    public HttpEntity<?> GetHash (@RequestParam String id) throws Exception {
        try {
            byte[] hash = digSignerService.CreateHash(id);

            HttpHeaders headers = new HttpHeaders();
            headers.add("Content-Type", "application/octet-stream");

            ContentDisposition contentDisposition = ContentDisposition
                    .builder("attachment")
                    .build();
            headers.setContentDisposition(contentDisposition);

            return new HttpEntity<>(hash, headers);
        }
        catch (Exception e) {
            logger.error("Проблема создания хеша для файла с id " + id +
                    " из-за ошибки: " + e.getMessage());
            return new ResponseEntity<>(e.getMessage(),
                    HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @RequestMapping(
            path = "/xml",
            method = RequestMethod.POST,
            consumes = MediaType.APPLICATION_XML_VALUE)
    public HttpEntity<?> GetXmlDsig (@RequestBody String source,
                                     @RequestParam String nodeId, @RequestParam String certId,
                                     @RequestParam @Nullable Boolean signatureOnly) {
        try {
            if (signatureOnly == null) {
                signatureOnly = true;
            }
            String signedXml = digSignerService.CreateXmlSignature(source, nodeId, certId, signatureOnly);

            HttpHeaders headers = new HttpHeaders();
            headers.add("Content-Type", "application/xml");

            ContentDisposition contentDisposition = ContentDisposition
                    .builder("attachment")
                    .filename(certId)
                    .build();
            headers.setContentDisposition(contentDisposition);

            return new HttpEntity<>(signedXml, headers);
        }
        catch (Exception e) {
            logger.error("Проблема создания/получения подписи XML файла" +
                    " из-за ошибки: " + e.getMessage());
            return new ResponseEntity<>(e.getMessage(),
                    HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @RequestMapping(
            path = "xml/validate",
            method = RequestMethod.POST,
            consumes = MediaType.APPLICATION_XML_VALUE)
    public ResponseEntity<?> ValidateXmlDsig (@RequestBody String source) {
        try {

            boolean result = digSignerService.ValidateXmlSignature(source);

            return new ResponseEntity<>(result,
                    HttpStatus.OK);
        }
        catch (Exception e) {
            logger.error("Проблема валидации xml подписи" +
                    " из-за ошибки: " + e.getMessage());
            return new ResponseEntity<>(e.getMessage(),
                    HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @RequestMapping(
            path = "xml/validatePKCS7",
            method = RequestMethod.POST,
            consumes = MediaType.APPLICATION_XML_VALUE)
    public ResponseEntity<?> ValidatePKCS7sig (@RequestParam String cntId,
                                               @RequestParam @Nullable String sigId) {
        try {
            boolean result;

            if (sigId.isEmpty() || sigId == null) {
                result = digSignerService.ValidateSignaturePKCS7File(cntId);
            } else {
                result = digSignerService.ValidateSignaturePKCS7File(sigId, cntId);
            }

            return new ResponseEntity<>(result,
                    HttpStatus.OK);
        }
        catch (Exception e) {
            logger.error("Проблема валидации подписи" +
                    " из-за ошибки: " + e.getMessage());
            return new ResponseEntity<>(e.getMessage(),
                    HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
}
