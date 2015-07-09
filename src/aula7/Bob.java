/*************************************************************************
*                         Criptografia - MIECOM                          *
*   Paulo Duarte, 58655                                                  *
*   António de Sousa, 58675                                              *
*   Data: 06/2013                                                        *
*                                                                        *
* Trabalho Aula 7                                                        *
* Pretende-se certicar as chaves publicas utilizadas no protocolo        *
* Station-to-Station com base em certicados X509.                        *
*                                                                        *
*                                                                        *
*                                                                        *
*                             Classe Cliente                             *
*************************************************************************/
package aula7;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public class Bob {
    
    
   private  String HMAC_SHA1_ALGORITHM;
   private static byte[] iv = { 0x0a, 0x01, 0x02, 0x03, 0x04, 0x0b, 0x0c, 0x0d, 0x0a, 0x01, 0x02, 0x03, 0x04, 0x0b, 0x0c, 0x0d };



    public Bob() {
        this.HMAC_SHA1_ALGORITHM = "HmacSHA1";
    }
   
       public String receive( CipherInputStream cis)  
    {
        String buffer = "";
       
        int test;
       try {       
           while ((test=cis.read())!=35) {
                 buffer = buffer + (char)test;
           }
       } catch (IOException ex) {
           Logger.getLogger(servidor.class.getName()).log(Level.SEVERE, null, ex);
       }
        return buffer;
    }
    
    
    
      public void send(String buffer, CipherOutputStream cos) {
       try {       
           cos.write(buffer.getBytes(), 0, buffer.length());
       } catch (IOException ex) {
           Logger.getLogger(servidor.class.getName()).log(Level.SEVERE, null, ex);
       }
       try {       
       
           cos.flush();
       } catch (IOException ex) {
           Logger.getLogger(servidor.class.getName()).log(Level.SEVERE, null, ex);
       }
       
    }
      
          /*
     * Converts a byte to hex digit and writes to the supplied buffer
     */
    private void byte2hex(byte b, StringBuffer buf) {
        char[] hexChars = { '0', '1', '2', '3', '4', '5', '6', '7', '8',
                            '9', 'A', 'B', 'C', 'D', 'E', 'F' };
        int high = ((b & 0xf0) >> 4);
        int low = (b & 0x0f);
        buf.append(hexChars[high]);
        buf.append(hexChars[low]);
    }

    /*
     * Converts a byte array to hex string
     */
    private String toHexString(byte[] block) {
        StringBuffer buf = new StringBuffer();

        int len = block.length;

        for (int i = 0; i < len; i++) {
             byte2hex(block[i], buf);
             if (i < len-1) {
                 buf.append(":");
             }
        }
        return buf.toString();
    }

    /*
     * Prints the usage of this test.
     */
    private void usage() {
        System.err.print("DHKeyAgreement usage: ");
        System.err.println("[-gen]");
    }

    // The 1024 bit Diffie-Hellman modulus values used by SKIP
    private static final byte skip1024ModulusBytes[] = {
        (byte)0xF4, (byte)0x88, (byte)0xFD, (byte)0x58,
        (byte)0x4E, (byte)0x49, (byte)0xDB, (byte)0xCD,
        (byte)0x20, (byte)0xB4, (byte)0x9D, (byte)0xE4,
        (byte)0x91, (byte)0x07, (byte)0x36, (byte)0x6B,
        (byte)0x33, (byte)0x6C, (byte)0x38, (byte)0x0D,
        (byte)0x45, (byte)0x1D, (byte)0x0F, (byte)0x7C,
        (byte)0x88, (byte)0xB3, (byte)0x1C, (byte)0x7C,
        (byte)0x5B, (byte)0x2D, (byte)0x8E, (byte)0xF6,
        (byte)0xF3, (byte)0xC9, (byte)0x23, (byte)0xC0,
        (byte)0x43, (byte)0xF0, (byte)0xA5, (byte)0x5B,
        (byte)0x18, (byte)0x8D, (byte)0x8E, (byte)0xBB,
        (byte)0x55, (byte)0x8C, (byte)0xB8, (byte)0x5D,
        (byte)0x38, (byte)0xD3, (byte)0x34, (byte)0xFD,
        (byte)0x7C, (byte)0x17, (byte)0x57, (byte)0x43,
        (byte)0xA3, (byte)0x1D, (byte)0x18, (byte)0x6C,
        (byte)0xDE, (byte)0x33, (byte)0x21, (byte)0x2C,
        (byte)0xB5, (byte)0x2A, (byte)0xFF, (byte)0x3C,
        (byte)0xE1, (byte)0xB1, (byte)0x29, (byte)0x40,
        (byte)0x18, (byte)0x11, (byte)0x8D, (byte)0x7C,
        (byte)0x84, (byte)0xA7, (byte)0x0A, (byte)0x72,
        (byte)0xD6, (byte)0x86, (byte)0xC4, (byte)0x03,
        (byte)0x19, (byte)0xC8, (byte)0x07, (byte)0x29,
        (byte)0x7A, (byte)0xCA, (byte)0x95, (byte)0x0C,
        (byte)0xD9, (byte)0x96, (byte)0x9F, (byte)0xAB,
        (byte)0xD0, (byte)0x0A, (byte)0x50, (byte)0x9B,
        (byte)0x02, (byte)0x46, (byte)0xD3, (byte)0x08,
        (byte)0x3D, (byte)0x66, (byte)0xA4, (byte)0x5D,
        (byte)0x41, (byte)0x9F, (byte)0x9C, (byte)0x7C,
        (byte)0xBD, (byte)0x89, (byte)0x4B, (byte)0x22,
        (byte)0x19, (byte)0x26, (byte)0xBA, (byte)0xAB,
        (byte)0xA2, (byte)0x5E, (byte)0xC3, (byte)0x55,
        (byte)0xE9, (byte)0x2F, (byte)0x78, (byte)0xC7
    };
    
      
        
public void run() throws IOException, InvalidKeySpecException, NoSuchAlgorithmException, IllegalStateException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, SignatureException, IllegalBlockSizeException, NoSuchProviderException, FileNotFoundException, ClassNotFoundException, CertificateException, Exception
{

     CipherInputStream cis = null;
    // Open a port and wait for a connection
     Socket cs = null;
     cs = new Socket("127.0.0.1", 3333);
     DataOutputStream out = new DataOutputStream(cs.getOutputStream());
     DataInputStream in = new DataInputStream(cs.getInputStream());

     byte[] keyBytes = new byte[in.readInt()];
     in.readFully(keyBytes);

     KeyFactory bobkf = KeyFactory.getInstance("DH");
     X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(keyBytes);
     PublicKey AlicePublicKey = bobkf.generatePublic(x509Spec);
   

     /*
     * Bob gets the DH parameters associated with Alice's public key. 
     * He must use the same parameters when he generates his own key
     * pair.
     */
    DHParameterSpec dhParamSpec = ((DHPublicKey)AlicePublicKey).getParams();

    System.out.println("G:" + dhParamSpec.getG());
    System.out.println("P:" + dhParamSpec.getP());
    
    SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
    
    ObjectOutputStream oos = null;
    ObjectInputStream ois = null;
    
       try {
           oos = new ObjectOutputStream(cs.getOutputStream());
       } catch (IOException ex) {
           Logger.getLogger(servidor.class.getName()).log(Level.SEVERE, null, ex);
       }
       try {
           ois = new  ObjectInputStream(cs.getInputStream());
       } catch (IOException ex) {
           Logger.getLogger(servidor.class.getName()).log(Level.SEVERE, null, ex);
       }
    
        BigInteger gx = null;
        
  
       try {
        gx = (BigInteger) ois.readObject();
         } catch (IOException ex) {
       Logger.getLogger(servidor.class.getName()).log(Level.SEVERE, null, ex);
         } catch (ClassNotFoundException ex) {
       Logger.getLogger(servidor.class.getName()).log(Level.SEVERE, null, ex);
         }
       
       System.out.println("gx:" + gx);
       BigInteger y = new BigInteger(512, random);
       BigInteger gy = dhParamSpec.getG().modPow(y, dhParamSpec.getP());
   
       try {
       oos.writeObject(gy);
       } catch (IOException ex) {
       Logger.getLogger(servidor.class.getName()).log(Level.SEVERE, null, ex);
       }
    
    System.out.println("gy:" + gy);
    
    BigInteger k = gx.modPow(y, dhParamSpec.getP());
    System.out.println("K:" + k);
       
    // Chave de sessão
    SecretKeySpec Ksess = null;

    MessageDigest md = MessageDigest.getInstance("SHA-256");
    md.update(k.toByteArray());
  
    byte byteData[] = md.digest();
       
       
    IvParameterSpec IV = new IvParameterSpec(iv);
    Ksess = null;
    Ksess = new SecretKeySpec(byteData, "AES");
    
    DESKeySpec sks = new DESKeySpec(k.toByteArray());
    SecretKeyFactory skf = SecretKeyFactory.getInstance("DES");
    SecretKey sk = skf.generateSecret(sks);
    Cipher enc = Cipher.getInstance("DES/ECB/PKCS5Padding");
    enc.init(Cipher.ENCRYPT_MODE, sk);
    Cipher dec = Cipher.getInstance("DES/ECB/PKCS5Padding");
    dec.init(Cipher.DECRYPT_MODE, sk);
    
    
    
    //*********************************************************************************** 
    Cipher bobCipher = null;
    bobCipher.init(Cipher.ENCRYPT_MODE, Ksess, IV);
    CipherOutputStream cos = new CipherOutputStream(cs.getOutputStream(), bobCipher);
    bobCipher.init(Cipher.DECRYPT_MODE, Ksess, IV);
    cis = new CipherInputStream(cs.getInputStream(), bobCipher);
    System.out.println("BOB: Execute PHASE1 ...");
    //************************************************************************************
    
    

    Signature sig = null;
       try {
           sig = Signature.getInstance("SHA1withRSA");
       } catch (NoSuchAlgorithmException ex) {
           Logger.getLogger(servidor.class.getName()).log(Level.SEVERE, null, ex);
       }
       
       
       PrivateKey BobPri = keyfromCert.converterP("bob.pk8");
        
       sig.initSign(BobPri);
       sig.update(gy.toByteArray());
       sig.update(gx.toByteArray());
       byte[] assinaturaXY = sig.sign(); 
       
       SealedObject sigXY = new SealedObject(assinaturaXY, enc);
       oos.writeObject(sigXY);
       
      
      // Recebe a chave publica do bob
      PublicKey alicePub = null;
   
      
      //*************************************************************************************************************************
      //                                     Valida o Certificado da Alice
      //************************************************************************************************************************
    
        ValidateCertPath.validateCer("ca.cer", "alice.cer");
   
   
      //*************************************************************************************************************************
      //                         Le a chave Publica a presente no certificado do Alice
      //************************************************************************************************************************
     
       alicePub= keyfromCert.getPublicKey("alice.cer");
  
      
      SealedObject sigXY2 = null;
      
      
      //********************************************************************************************************
      //                                    Recebe a assinatura 
      //********************************************************************************************************

     
       sigXY2 = (SealedObject) ois.readObject();
    
      
      //********************************************************************************************************
      //                                    Decifra a assinatura 
      //********************************************************************************************************
      
      byte[] assinaturaXY2 = null;
      assinaturaXY2 = (byte[]) sigXY2.getObject(dec);
      System.out.println(assinaturaXY2);
      
      //********************************************************************************************************
      //**********************************       VAidação  da assinatura        ********************************
      //********************************************************************************************************
      sig.initVerify(alicePub);
      sig.update(gx.toByteArray());
      sig.update(gy.toByteArray());
            

      
       if( sig.verify(assinaturaXY2) ) {
           System.out.println("Sucesso - Certificado Validado");
       }
       else {
           System.out.println("Sucesso - Certificado Inválido");
       }
           
    
    
//    Buffer= Buffer+"#";
//    MAC_recebido = receive(cis);
//    System.out.println("MAC recebido: " + MAC_recebido);

    

    cs.close();
}


/***********************************************************************************************************/
/*                                              HMAC                                                       */
/***********************************************************************************************************/


public static String hmacDigest(String msg, String keyString, String algo) throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeyException {
String digest = null;

  SecretKeySpec key = new SecretKeySpec((keyString).getBytes("UTF-8"), algo);
  Mac mac = Mac.getInstance(algo);
  mac.init(key);

  byte[] bytes = mac.doFinal(msg.getBytes("ASCII"));

  StringBuilder hash = new StringBuilder();
  for (int i = 0; i < bytes.length; i++) {
    String hex = Integer.toHexString(0xFF & bytes[i]);
    if (hex.length() == 1) {
      hash.append('0');
    }
    hash.append(hex);
  }
  digest = hash.toString();

return digest;
}



 public static void main(String[] args) throws IOException, InvalidKeySpecException, 
         NoSuchAlgorithmException, IllegalStateException, InvalidKeyException, NoSuchPaddingException,
         InvalidAlgorithmParameterException, SignatureException, IllegalBlockSizeException, 
         NoSuchProviderException, FileNotFoundException, ClassNotFoundException, CertificateException, Exception, Exception {
     
     Bob b = new Bob();
     b.run();
}
    
    
}