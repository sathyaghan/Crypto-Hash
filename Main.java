package iit.ece443.prj01;

import java.security.MessageDigest;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Main
{
    public static void main(String[] args)
        throws Exception
    {
        verifyMD5(); //Calls the function that does validation of MD5
        System.out.println();
        perfMD5(); //Does a performance evaluation of the MD5 Hashing Algorithm

        System.out.println();
        
        verifySHA256(); //Calls the function that does validation of SHA 256
        System.out.println();
        perfSHA256(); //Does a performance evaluation of the SHA 256 Hashing Algorithm
        
        System.out.println();
        
        verifySHA512(); //Calls the function that does validation of SHA 512
        System.out.println();
        perfSHA512(); //Does a performance evaluation of the SHA 512 Hashing Algorithm
        
        System.out.println();

        verifyAESGCM(); //Calls the function that does validation of AES-GCM
        System.out.println();
        perfAESGCM(); //Does a performance evaluation of the AES-GCM Algorithm
        
        System.out.println();
        
        verifyAESCBC(); //Calls the function that does validation of AES-CBC
        System.out.println();
        perfAESCBC(); //Does a performance evaluation of the AES-CBC Algorithm
    }
    
    private static String hexString(byte[] buf)
    {
        StringBuilder sb = new StringBuilder();
        for (byte b: buf)
            sb.append(String.format("%02X", b));
        return sb.toString();
    }
    
    private static void verifyMD5()
        throws Exception
    {
        MessageDigest md = MessageDigest.getInstance("MD5");
        
        String str = "Hello world!";
        String md5 = "86FB269D190D2C85F6E0468CECA42A20";
        
        md.update(str.getBytes("UTF-8"));
        byte[] hash = md.digest();
        
        System.out.printf("MD5 of [%s]%n", str);
        System.out.printf("Computed: %s%n", hexString(hash));
        System.out.printf("Expected: %s%n", md5); 
    }
    
    
    private static void perfMD5()
        throws Exception
    {
        int MB = 256;
        
        byte[] buf = new byte[MB*1024*1024];
        Arrays.fill(buf, (byte)0);
        
        MessageDigest md = MessageDigest.getInstance("MD5");

        long start = System.currentTimeMillis();
        md.update(buf);
        byte[] hash = md.digest();
        long stop = System.currentTimeMillis();
        
        System.out.printf("MD5 of %dMB 0x00%n", MB);
        System.out.printf("Computed: %s%n", hexString(hash));
        
        System.out.printf("Time used: %d ms%n", stop-start); 
        System.out.printf("Performance: %.2f MB/s%n", MB*1000.0/(stop-start)); 
    }
    
    private static void verifySHA256()
        throws Exception
    {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        
        String str = "Hello world!";
        
        md.update(str.getBytes("UTF-8"));
        byte[] hash = md.digest();
        
        System.out.printf("SHA 256 of [%s]%n", str);
        System.out.printf("Computed: %s%n", hexString(hash)); 
    }
    
    private static void perfSHA256()
        throws Exception
    {
        int MB = 256;
        
        byte[] buf = new byte[MB*1024*1024];
        Arrays.fill(buf, (byte)0);
        
        MessageDigest md = MessageDigest.getInstance("SHA-256");

        long start = System.currentTimeMillis();
        md.update(buf);
        byte[] hash = md.digest();
        long stop = System.currentTimeMillis();
        
        System.out.printf("SHA256 of %dMB 0x00%n", MB);
        System.out.printf("Computed: %s%n", hexString(hash));
        
        System.out.printf("Time used: %d ms%n", stop-start); 
        System.out.printf("Performance: %.2f MB/s%n", MB*1000.0/(stop-start)); 
    }
    
    private static void verifySHA512()
        throws Exception
    {
        MessageDigest md = MessageDigest.getInstance("SHA-512");
        
        String str = "Hello world!";
        
        md.update(str.getBytes("UTF-8"));
        byte[] hash = md.digest();
        
        System.out.printf("SHA 512 of [%s]%n", str);
        System.out.printf("Computed: %s%n", hexString(hash)); 
    }
    
    private static void perfSHA512()
        throws Exception
    {
        int MB = 256;
        
        byte[] buf = new byte[MB*1024*1024];
        Arrays.fill(buf, (byte)0);
        
        MessageDigest md = MessageDigest.getInstance("SHA-512");

        long start = System.currentTimeMillis();
        md.update(buf);
        byte[] hash = md.digest();
        long stop = System.currentTimeMillis();
        
        System.out.printf("SHA512 of %dMB 0x00%n", MB);
        System.out.printf("Computed: %s%n", hexString(hash));
        
        System.out.printf("Time used: %d ms%n", stop-start); 
        System.out.printf("Performance: %.2f MB/s%n", MB*1000.0/(stop-start)); 
    }
    
    private static void verifyAESGCM()
        throws Exception
    {
        String msg = "Hello world!";
        byte[] buf = new byte[1000];
        
        byte[] iv = new byte[12];
        Arrays.fill(iv, (byte)0);
        GCMParameterSpec ivSpec = new GCMParameterSpec(128, iv);
        
        byte[] key = new byte[16];
        Arrays.fill(key, (byte)1);
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

        byte[] plaintext = msg.getBytes("UTF-8");

        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        int len = cipher.update(plaintext, 0, plaintext.length, buf);
        len += cipher.doFinal(buf, len);
        
        byte[] ciphertext = Arrays.copyOf(buf, len-16);
        byte[] mac = Arrays.copyOfRange(buf, len-16, len);
        
        System.out.printf("AES/GCM of [%s]%n", msg);
        System.out.printf("Plaintext:  %s%n", hexString(plaintext));
        System.out.printf("Ciphertext: %s%n", hexString(ciphertext));
        System.out.printf("MAC:        %s%n", hexString(mac));
        
        System.out.println("When correct ciphertext and mac are used for decryption: ");
        
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        int len2 = cipher.update(ciphertext, 0, ciphertext.length, buf);
        len2 += cipher.update(mac, 0, mac.length, buf, len2);
        len2 += cipher.doFinal(buf, len2);
        byte[] plaintext2 = Arrays.copyOf(buf, len2);
        System.out.printf("Decrypted:  %s%n", hexString(plaintext2));
        
        //ciphertext = "[B567893e5d".getBytes("UTF-8");
        //ciphertext = "[B@20322d26".getBytes("UTF-8");
        
        //Checking for decryption with a bad tag, where the cipher-text and mac are interchanged
        
        System.out.println("When incorrect ciphertext and mac are used for decryption: ");
        try
        {
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        int len3 = cipher.update(mac, 0, mac.length, buf);
        len3 += cipher.update(ciphertext, 0, ciphertext.length, buf, len3);
        len3 += cipher.doFinal(buf, len3);
        byte[] plaintext3 = Arrays.copyOf(buf, len3);
        System.out.printf("Decrypted:  %s%n", hexString(plaintext3));
        } 
        catch(Exception e)
        {
          System.out.println("Either ciphertext or mac has been modified!");
        }
    }

    private static void perfAESGCM()
        throws Exception
    {
        int MB = 64;
        
        byte[] plaintext = new byte[MB*1024*1024];
        Arrays.fill(plaintext, (byte)0);
        
        byte[] buf = new byte[MB*1024*1024+16];
        
        byte[] iv = new byte[12];
        Arrays.fill(iv, (byte)0);
        GCMParameterSpec ivSpec = new GCMParameterSpec(128, iv);
        
        byte[] key = new byte[16];
        Arrays.fill(key, (byte)1);
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

        long startE = System.currentTimeMillis();
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        int len = cipher.update(plaintext, 0, plaintext.length, buf);
        len += cipher.doFinal(buf, len);
        long stopE = System.currentTimeMillis();
        
        byte[] ciphertext = Arrays.copyOf(buf, len-16);
        byte[] mac = Arrays.copyOfRange(buf, len-16, len);
        
        System.out.printf("AES/GCM of %dMB 0x00%n", MB);
        System.out.printf("Plaintext:  %s[MD5]%n",
            hexString(MessageDigest.getInstance("MD5").digest(plaintext)));
        System.out.printf("MAC:        %s%n", hexString(mac));
        
        long startD = System.currentTimeMillis();
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        int len2 = cipher.update(ciphertext, 0, ciphertext.length, buf);
        len2 += cipher.update(mac, 0, mac.length, buf, len2);
        len2 += cipher.doFinal(buf, len2);
        long stopD = System.currentTimeMillis();
        
        byte[] plaintext2 = Arrays.copyOf(buf, len2);
        System.out.printf("Decrypted:  %s[MD5]%n",
            hexString(MessageDigest.getInstance("MD5").digest(plaintext2)));
        
        System.out.printf(
            "Time used: encryption %d ms, decryption %d ms%n",
            stopE-startE, stopD-startD); 
        System.out.printf(
            "Performance: encryption %.2f MB/s, decryption %.2f MB/s%n",
            MB*1000.0/(stopE-startE), MB*1000.0/(stopD-startD)); 
    }
    
    //BONUS PART: Validation and Performance of AES-CBC with padding
    
    private static void verifyAESCBC()
        throws Exception
    {
        String msg = "Hello world!";
        byte[] buf = new byte[1000];
        
        byte[] iv = new byte[16];
        Arrays.fill(iv, (byte)0);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        
        byte[] key = new byte[16];
        Arrays.fill(key, (byte)1);
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        byte[] plaintext = msg.getBytes("UTF-8");

        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        int len = cipher.update(plaintext, 0, plaintext.length, buf);
        len += cipher.doFinal(buf, len);
        
        byte[] ciphertext = Arrays.copyOf(buf, len);
       // byte[] mac = Arrays.copyOfRange(buf, len-16, len);
        
        System.out.printf("AES/CBC of [%s]%n", msg);
        System.out.printf("Plaintext:  %s%n", hexString(plaintext));
        System.out.printf("Ciphertext: %s%n", hexString(ciphertext));
        //System.out.printf("MAC:        %s%n", hexString(mac));
        
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        int len2 = cipher.update(ciphertext, 0, ciphertext.length, buf);
        //len2 += cipher.update(ciphertext, 0, ciphertext.length, buf, len2);
        len2 += cipher.doFinal(buf, len2);
        
        byte[] plaintext2 = Arrays.copyOf(buf, len2);
        System.out.printf("Decrypted:  %s%n", hexString(plaintext2));
    }

    private static void perfAESCBC()
        throws Exception
    {
        int MB = 64;
        
        byte[] plaintext = new byte[MB*1024*1024];
        Arrays.fill(plaintext, (byte)0);
        
        byte[] buf = new byte[MB*1024*1024+16];
        
        byte[] iv = new byte[16];
        Arrays.fill(iv, (byte)0);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        
        byte[] key = new byte[16];
        Arrays.fill(key, (byte)1);
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        long startE = System.currentTimeMillis();
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        int len = cipher.update(plaintext, 0, plaintext.length, buf);
        len += cipher.doFinal(buf, len);
        long stopE = System.currentTimeMillis();
        
        byte[] ciphertext = Arrays.copyOf(buf, len);
        
        System.out.printf("AES/CBC of %dMB 0x00%n", MB);
        System.out.printf("Plaintext:  %s[MD5]%n",
            hexString(MessageDigest.getInstance("MD5").digest(plaintext)));
        System.out.printf("Ciphertext: %s[MD5]%n", 
    		hexString(MessageDigest.getInstance("MD5").digest(ciphertext)));
        
        long startD = System.currentTimeMillis();
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        int len2 = cipher.update(ciphertext, 0, ciphertext.length, buf);
        len2 += cipher.doFinal(buf, len2);
        long stopD = System.currentTimeMillis();
        
        byte[] plaintext2 = Arrays.copyOf(buf, len2);
        System.out.printf("Decrypted:  %s[MD5]%n",
            hexString(MessageDigest.getInstance("MD5").digest(plaintext2)));
        
        System.out.printf(
            "Time used: encryption %d ms, decryption %d ms%n",
            stopE-startE, stopD-startD); 
        System.out.printf(
            "Performance: encryption %.2f MB/s, decryption %.2f MB/s%n",
            MB*1000.0/(stopE-startE), MB*1000.0/(stopD-startD)); 
    }
}
