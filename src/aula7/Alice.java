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
*                             Classe Servidor                            *
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
import java.net.ServerSocket;
import java.net.Socket;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;



  
class servidor extends Thread {
    
   private static byte[] iv = { 0x0a, 0x01, 0x02, 0x03, 0x04, 0x0b, 0x0c, 0x0d, 0x0a, 0x01, 0x02, 0x03, 0x04, 0x0b, 0x0c, 0x0d };
   Socket cs;
   KeyPair aliceKpair;
   DHParameterSpec dhsp;
   
   
    
   public servidor(Socket cs, KeyPair aKpair, DHParameterSpec dhSkipParamSpec ) {
        this.cs = cs;
        this.aliceKpair = aKpair;
        dhsp = dhSkipParamSpec;
 
        
    }

    
    public String receive( CipherInputStream cis)  
    {
        String buffer = "";
       
        int test;
       try {       
           while ((test=cis.read())!=35) {
                 System.out.println(test);
                 System.out.println("Texto Limpo: " + (char)test);
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
    
    
    
 /***********************************************************************************************************/
 /*                                              HMAC                                                       */
 /***********************************************************************************************************/
       
    public static String hmacDigest(String msg, String keyString, String algo) {
       try {
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
           
       } catch (UnsupportedEncodingException ex) {
           Logger.getLogger(servidor.class.getName()).log(Level.SEVERE, null, ex);
       } catch (NoSuchAlgorithmException ex) {
           Logger.getLogger(servidor.class.getName()).log(Level.SEVERE, null, ex);
       } catch (InvalidKeyException ex) {
           Logger.getLogger(servidor.class.getName()).log(Level.SEVERE, null, ex);
       }
       return null;
  }
      
    
   /***********************************************************************************************************/
   /*               Converts a byte to hex digit and writes to the supplied buffer                            */
   /***********************************************************************************************************/
         

      
      
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
   
    

/**************************************************************************************************************/
/***************************************        THREAD         ************************************************/
/**************************************************************************************************************/


public void run() 
{
    
    
try {
   DataOutputStream out = null;
   DataInputStream in = null;
   byte[] bobPubKeyEnc = null;
   KeyFactory aliceKeyFac = null;
   KeyAgreement aliceKeyAgree = null;
   CipherOutputStream cos = null;
   CipherInputStream cis = null;
   IvParameterSpec IV = new IvParameterSpec(iv);
   Cipher aliceCipher = null;
   ObjectOutputStream oos = null;
   ObjectInputStream ois = null;

   
                       
                       
      try {
          out = new DataOutputStream(cs.getOutputStream());
      } catch (IOException ex) {
          Logger.getLogger(servidor.class.getName()).log(Level.SEVERE, null, ex);
      }


       try {
           in = new DataInputStream(cs.getInputStream());
       } catch (IOException ex) {
           Logger.getLogger(servidor.class.getName()).log(Level.SEVERE, null, ex);
       }

       // A Alice envia a chave Publica... 
       System.out.println("A Alice envia a chave Publica...");
       byte[] keyBytes = aliceKpair.getPublic().getEncoded();

       try {
           out.writeInt(keyBytes.length);
       } catch (IOException ex) {
           Logger.getLogger(servidor.class.getName()).log(Level.SEVERE, null, ex);
       }

       try {
           out.write(keyBytes);
       } catch (IOException ex) {
           Logger.getLogger(servidor.class.getName()).log(Level.SEVERE, null, ex);
       }


               
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


      SecureRandom random = null;
      
      try {
          random = SecureRandom.getInstance("SHA1PRNG");
      } catch (NoSuchAlgorithmException ex) {
          Logger.getLogger(servidor.class.getName()).log(Level.SEVERE, null, ex);
      }
      
       BigInteger x = new BigInteger(512, random);
       BigInteger gx = dhsp.getG().modPow(x, dhsp.getP());
       
       System.out.println("gx:" + gx);
       try {
       oos.writeObject(gx);
       } catch (IOException ex) {
       Logger.getLogger(servidor.class.getName()).log(Level.SEVERE, null, ex);
       }
               
       BigInteger gy = null;
                
       try {
           gy = (BigInteger) ois.readObject();
       } catch (IOException ex) {
           Logger.getLogger(servidor.class.getName()).log(Level.SEVERE, null, ex);
       } catch (ClassNotFoundException ex) {
           Logger.getLogger(servidor.class.getName()).log(Level.SEVERE, null, ex);
       }

       System.out.println("gy:" + gy);
       BigInteger k = gy.modPow(x, dhsp.getP());
       System.out.println("K:" + k);
               
       // Chave de sessão
       SecretKeySpec Ksess = null;
       
       //*****************************************************************************************************************
       //                    Função de hash para diminuir o tamanho da chave de sessão
       //*****************************************************************************************************************
       
       
       MessageDigest md = null;
 
       try {
       md = MessageDigest.getInstance("SHA-256");
       } catch (NoSuchAlgorithmException ex) {
        Logger.getLogger(servidor.class.getName()).log(Level.SEVERE, null, ex);
        }
        md.update(k.toByteArray());
        byte byteData[] = md.digest();

        Ksess = null;
        Ksess = new SecretKeySpec(byteData, "AES");

        
        //*******************************************************************************************************
        //                criação de um canal seguro utilizando a chave de sessão
        //*******************************************************************************************************
        
        try {
          aliceCipher = Cipher.getInstance("AES/CFB8/NoPadding");
       } catch (NoSuchAlgorithmException ex) {
          Logger.getLogger(servidor.class.getName()).log(Level.SEVERE, null, ex);
       } catch (NoSuchPaddingException ex) {
          Logger.getLogger(servidor.class.getName()).log(Level.SEVERE, null, ex);
       }

       try {
          aliceCipher.init(Cipher.DECRYPT_MODE, Ksess, IV);
       } catch (InvalidKeyException ex) {
          Logger.getLogger(servidor.class.getName()).log(Level.SEVERE, null, ex);
       } catch (InvalidAlgorithmParameterException ex) {
          Logger.getLogger(servidor.class.getName()).log(Level.SEVERE, null, ex);
       }

       try {
          cis = new CipherInputStream(cs.getInputStream(), aliceCipher);
       } catch (IOException ex) {
          Logger.getLogger(servidor.class.getName()).log(Level.SEVERE, null, ex);
       }
       try {


       aliceCipher.init(Cipher.ENCRYPT_MODE, Ksess, IV);
       } catch (InvalidKeyException ex) {
          Logger.getLogger(servidor.class.getName()).log(Level.SEVERE, null, ex);
       } catch (InvalidAlgorithmParameterException ex) {
          Logger.getLogger(servidor.class.getName()).log(Level.SEVERE, null, ex);
       }
       try {
           cos = new CipherOutputStream(cs.getOutputStream(), aliceCipher);
       } catch (IOException ex) {
           Logger.getLogger(servidor.class.getName()).log(Level.SEVERE, null, ex);
       }
               

               
      
      //************************************************************************************************************
      //***************   Para posteriormente enviar a assinatura(X,Y) cifrada com a chave privada *****************
      //************************************************************************************************************
       
       DESKeySpec sks = new DESKeySpec(k.toByteArray());
       SecretKeyFactory skf = SecretKeyFactory.getInstance("DES");
       SecretKey sk = skf.generateSecret(sks);
       Cipher enc = Cipher.getInstance("DES/ECB/PKCS5Padding");
       enc.init(Cipher.ENCRYPT_MODE, sk);
       Cipher dec = Cipher.getInstance("DES/ECB/PKCS5Padding");
       dec.init(Cipher.DECRYPT_MODE, sk);

               
      //************************************************************************************************************************
      //****************************** Inicio da construção da assinatura digital **********************************************
      //************************************************************************************************************************
      Signature sig = null;

      try {
          sig = Signature.getInstance("SHA1withRSA");
      } catch (NoSuchAlgorithmException ex) {
          Logger.getLogger(servidor.class.getName()).log(Level.SEVERE, null, ex);
      }
      
          
      ////////////////////////////////////////////////////////////////////////////////////////
      // Recebe a chave publica do bob
      PublicKey bobPub = null;
   
      
      //*************************************************************************************************************************
      //                                     Valida o Certificado do BOB
      //************************************************************************************************************************
      try {
        ValidateCertPath.validateCer("ca.cer", "bob.cer");
    } catch (Exception ex) {
        Logger.getLogger(servidor.class.getName()).log(Level.SEVERE, null, ex);
    }
   
      //*************************************************************************************************************************
      //                         Le a chave Publica a presente no certificado do BOB
      //************************************************************************************************************************
      try {
       bobPub= keyfromCert.getPublicKey("bob.cer");
      } catch (CertificateException ex) {
        Logger.getLogger(servidor.class.getName()).log(Level.SEVERE, null, ex);
      } catch (FileNotFoundException ex) {
        Logger.getLogger(servidor.class.getName()).log(Level.SEVERE, null, ex);
      }
      

      
      
      
      SealedObject sigXY2 = null;
      
      
      //********************************************************************************************************
      //                                    Recebe a assinatura 
      //********************************************************************************************************

      try {
          sigXY2 = (SealedObject) ois.readObject();
      } catch (IOException ex) {
          Logger.getLogger(servidor.class.getName()).log(Level.SEVERE, null, ex);
      } catch (ClassNotFoundException ex) {
          Logger.getLogger(servidor.class.getName()).log(Level.SEVERE, null, ex);
      }
      
      //********************************************************************************************************
      //                                    Decifra a assinatura 
      //********************************************************************************************************
      
      byte[] assinaturaXY2 = null;
      try {
          assinaturaXY2 = (byte[]) sigXY2.getObject(dec);
      } catch (IOException ex) {
          Logger.getLogger(servidor.class.getName()).log(Level.SEVERE, null, ex);
      } catch (ClassNotFoundException ex) {
          Logger.getLogger(servidor.class.getName()).log(Level.SEVERE, null, ex);
      } catch (IllegalBlockSizeException ex) {
          Logger.getLogger(servidor.class.getName()).log(Level.SEVERE, null, ex);
      } catch (BadPaddingException ex) {
          Logger.getLogger(servidor.class.getName()).log(Level.SEVERE, null, ex);
      }

      System.out.println(assinaturaXY2);
      
      //*************************************************************************************************************************
      //**********************************       VAidação  da assinatura        *************************************************
      //*************************************************************************************************************************
      sig.initVerify(bobPub);

       try {
           sig.update(gy.toByteArray());
             } catch (SignatureException ex) {
           Logger.getLogger(servidor.class.getName()).log(Level.SEVERE, null, ex);
       }
       
       try {
           sig.update(gx.toByteArray());
             } catch (SignatureException ex) {
           Logger.getLogger(servidor.class.getName()).log(Level.SEVERE, null, ex);
       }

       try {
           if( sig.verify(assinaturaXY2) ) {
               System.out.println("Sucesso - Certificado Validado");
           }
           else {
               System.out.println("Sucesso - Certificado Inválido");
           }
           } catch (SignatureException ex) {
           Logger.getLogger(servidor.class.getName()).log(Level.SEVERE, null, ex);
       }
       
      //*************************************************************************************************************************
      //                         Le a chave Privada Presente no PK8
      //************************************************************************************************************************
      PrivateKey AlicePri = null;
   
      try {
       AlicePri = keyfromCert.converterP("alice.pk8");
    } catch (FileNotFoundException ex) {
        Logger.getLogger(servidor.class.getName()).log(Level.SEVERE, null, ex);
    } catch (IOException ex) {
        Logger.getLogger(servidor.class.getName()).log(Level.SEVERE, null, ex);
    } catch (ClassNotFoundException ex) {
        Logger.getLogger(servidor.class.getName()).log(Level.SEVERE, null, ex);
    }
      
      
      //*************************************************************************************************************************
      //                                   Esta a gerar a assinatura da Alice     
      //*************************************************************************************************************************
      
      sig.initSign(AlicePri);
      
      try {
          sig.update(gx.toByteArray());
      } catch (SignatureException ex) {
          Logger.getLogger(servidor.class.getName()).log(Level.SEVERE, null, ex);
      }
                  
      try {
          sig.update(gy.toByteArray());
      } catch (SignatureException ex) {
          Logger.getLogger(servidor.class.getName()).log(Level.SEVERE, null, ex);
      }
      
     byte[] assinaturaXY = null;

      try {
         assinaturaXY = sig.sign();
      } catch (SignatureException ex) {
          Logger.getLogger(servidor.class.getName()).log(Level.SEVERE, null, ex);
      }
       
       
      SealedObject sigXY = new SealedObject(assinaturaXY, enc);
      oos.writeObject(sigXY);

        
       
         
       } catch (InvalidKeyException ex) {
           Logger.getLogger(servidor.class.getName()).log(Level.SEVERE, null, ex);
       } catch (NoSuchAlgorithmException ex) {
           Logger.getLogger(servidor.class.getName()).log(Level.SEVERE, null, ex);
       } catch (InvalidKeySpecException ex) {
           Logger.getLogger(servidor.class.getName()).log(Level.SEVERE, null, ex);
       } catch (NoSuchPaddingException ex) {
           Logger.getLogger(servidor.class.getName()).log(Level.SEVERE, null, ex);
       } catch (IOException ex) {
           Logger.getLogger(servidor.class.getName()).log(Level.SEVERE, null, ex);
       } catch (IllegalBlockSizeException ex) {
           Logger.getLogger(servidor.class.getName()).log(Level.SEVERE, null, ex);
       }
                  

       
        // envia a mensagem
        //
        //               String msg= "texto limplo:Mensagem para enviar num canal seguro e autenticado#";
        //               System.out.println("MENSAGEM a enviar: " + msg);
        //               send(msg, cos);

        // Envia o MAC 
        //********************************         MAC       ********************************************************
        //***********************************************************************************************************
        //String mac = hmacDigest(msg, toHexString(k2) , "HmacSHA1");
        // mac = mac + "#";
        // System.out.println("MENSAGEM A ENVIAR HMAC : "+ mac);
        // send(mac, cos);

     
      
    }
}



/**************************************************************************************************************/
/**************************************************************************************************************/
public class Alice {

public static void main(String[] args) throws InvalidKeyException, IOException, InvalidParameterSpecException {

    DHParameterSpec dhSkipParamSpec;
    AlgorithmParameterGenerator paramGen = null;
    KeyPairGenerator aliceKpairGen = null;
    System.out.println ("Criar os Parametros Diffie-Hellman");

    try {            
        paramGen = AlgorithmParameterGenerator.getInstance("DH");
    } catch (NoSuchAlgorithmException ex) {
        Logger.getLogger(Alice.class.getName()).log(Level.SEVERE, null, ex);
    }
    
    paramGen.init(1024);
    AlgorithmParameters params = paramGen.generateParameters();
    dhSkipParamSpec = (DHParameterSpec)params.getParameterSpec(DHParameterSpec.class);
   
    System.out.println("G: " + dhSkipParamSpec.getG());
    System.out.println("P: " + dhSkipParamSpec.getP());
    System.out.println("ALICE: Gerar um par de chaves ...");
    

    try {           
    aliceKpairGen = KeyPairGenerator.getInstance("DH");
    } catch (NoSuchAlgorithmException ex) {
        Logger.getLogger(Alice.class.getName()).log(Level.SEVERE, null, ex);
    }

    try {           
    aliceKpairGen.initialize(dhSkipParamSpec);
    } catch (InvalidAlgorithmParameterException ex) {
        Logger.getLogger(Alice.class.getName()).log(Level.SEVERE, null, ex);
    }


    // gerar o par de chaves
    // agora ja é possivel ver a chave Privada e publica
    KeyPair aliceKpair = aliceKpairGen.generateKeyPair();

    System.out.println(aliceKpair.getPublic());
    ServerSocket ss = new ServerSocket(3333);
    keyfromCert pk = new keyfromCert();
    

    // incilialização do socket
    Socket cs = null;
    System.out.println("Listening on port 3333 ...");

     while (true)
    {
            cs = ss.accept();
            new servidor (cs, aliceKpair, dhSkipParamSpec).start();
    }


}
}
