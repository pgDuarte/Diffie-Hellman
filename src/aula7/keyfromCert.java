package aula7;

import java.io.*;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;


public class keyfromCert {
 
            
//    public static void main(String[] args) throws InvalidKeySpecException, NoSuchAlgorithmException, FileNotFoundException, IOException, ClassNotFoundException, Exception {
//  
//        String pkcer = args[0];
//        String pk8 = args[1];
//        
//        PublicKey pKey = getPublicKey(pkcer);       
//        PrivateKey privKey = converterP(pk8);
//        
//        System.out.println(pKey);
//        System.out.println(privKey);
//        
//    }
    
    //******************************************* Vai buscar a chave publica ao .cer *************************************
    public static PublicKey getPublicKey(String pkfile) throws CertificateException, FileNotFoundException {
        
        FileInputStream fin = new FileInputStream(pkfile);
        CertificateFactory f = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate)f.generateCertificate(fin);
        PublicKey pk = certificate.getPublicKey();
        
        return pk;
        
    }
    
    
    //`*************** Vai buscar a chave privada a um PK8 ********************************************************
    public static PrivateKey converterP(String arg) throws InvalidKeySpecException, NoSuchAlgorithmException, FileNotFoundException, IOException, ClassNotFoundException {
        
        
        InputStream pkey = new FileInputStream(arg);
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        int nRead;
        byte[] data = new byte[16384];

        while ((nRead = pkey.read(data, 0, data.length)) != -1) {
            buffer.write(data, 0, nRead);
        }

        buffer.flush();

        byte[] encodedKey = buffer.toByteArray();
        
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encodedKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        
        return keyFactory.generatePrivate(keySpec);
    }
    
   
    
}
