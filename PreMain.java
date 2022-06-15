package com.oxagent;

import javassist.*;
import java.io.*;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.IllegalClassFormatException;
import java.lang.instrument.Instrumentation;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.ProtectionDomain;
import java.util.HashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class PreMain {
    public static void premain(String agentArgs, Instrumentation inst) throws Exception {

        if (agentArgs == null) {
            print_error("Please give me key to setup, xxx.jar=xxxxx");
            return;
        }else{
            print_good("I got you key,Patching~");
        }

        // check hash
        HashMap<String, String> hashArray = new HashMap<String, String>();

        hashArray.put("Cobalt Strike 4.5 (December 14, 2021)", "a5e980aac32d9c7af1d2326008537c66d55d7d9ccf777eb732b2a31f4f7ee523");
        hashArray.put("Cobalt Strike 4.4 (August 04, 2021) ", "7af9c759ac78da920395debb443b9007fdf51fa66a48f0fbdaafb30b00a8a858");
        hashArray.put("Cobalt Strike 4.3 (March 17, 2021) [bug fixes]", "c3c243e6218f7fbaaefb916943f500722644ec396cf91f31a30c777c2d559465");
        hashArray.put("Cobalt Strike 4.3 (March 3, 2021)", "02fa5afe9e58cb633328314b279762a03894df6b54c0129e8a979afcfca83d51");
        hashArray.put("Cobalt Strike 4.2 (November 6, 2020)", "56a53682084c46813a5157d73d7917100c9979b67e94b05c1b3244469e7ee07a");
        hashArray.put("Cobalt Strike 4.1 (June 25, 2020)", "1f2c29099ba7de0f7f05e0ca0efb58b56ec422b65d1c64e66633fa9d8f469d4f");
        hashArray.put("Cobalt Strike 4.0 (February 22, 2020) [bug fixes]", "10fe0fcdb6b89604da379d9d6bca37b8279f372dc235bbaf721adfd83561f2b3");
        hashArray.put("Cobalt Strike 4.0 (December 5, 2019)", "558f61bfab60ef5e6bec15c8a6434e94249621f53e7838868cdb3206168a0937");

        print_info("Hey! guys,I'll check file sha256 hash,Please wait me about 10s......");

        File file = new File("cobaltstrike.jar");

        if(!file.exists()){
            print_error("Hey guys,Please rename your xxx.jar to cobaltstrike.jar Thanks!");
            System.exit(1);
        }else{
            print_good("Loading cobaltstrike.jar");
        }


        String FileHash = getHash(file);

        boolean isTrueFile = false;

        System.out.println(FileHash);
        for (String version : hashArray.keySet()) {
            if(hashArray.get(version).equals(FileHash)){
                print_good("File: " + file + "; Version: " + version + "; SHA256: " + hashArray.get(version));
                isTrueFile = true;
            }

        }
        if(!isTrueFile){
            print_error("SHA256: " + FileHash + " Fuck off! Get out! Bad cobaltstrike.jar");
            System.exit(1);
        }

        inst.addTransformer(new CobaltStrikeTransformer(agentArgs), true);
    }

    public static final String scrub(String var0) {
        return var0 == null ? null : var0.replace('\u001b', '.');
    }
    public static final void print_good(String var0) {
        System.out.println("\u001b[01;32m[+]\u001b[0m " + scrub(var0));
    }
    public static final void print_error(String var0) {
        System.out.println("\u001b[01;31m[-]\u001b[0m " + scrub(var0));
    }
    public static final void print_info(String var0) {
        System.out.println("\u001b[01;34m[*]\u001b[0m " + scrub(var0));
    }
    public static final void print_warn(String var0) {
        System.out.println("\u001b[01;33m[!]\u001b[0m " + scrub(var0));
    }

    public static final void print_stat(String var0) {
        System.out.println("\u001b[01;35m[*]\u001b[0m " + scrub(var0));
    }

    static class CobaltStrikeTransformer implements ClassFileTransformer {
        private final ClassPool classPool = ClassPool.getDefault();
        private final String hexkey;

        public CobaltStrikeTransformer(String args) {
            this.hexkey = args;
            print_info(args);
        }
        @Override
        public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined, ProtectionDomain protectionDomain, byte[] classfileBuffer) throws IllegalClassFormatException {

            //return new byte[0];
            //System.out.println(className);
            try {
                if (className == null) {
                    return classfileBuffer;
                } else if (className.equals("sun/management/VMManagementImpl")) {
                    print_good("Patch exit");
                    CtClass cls = classPool.makeClass(new ByteArrayInputStream(classfileBuffer));
                    CtMethod cmsave = cls.getDeclaredMethod("getVmArguments");
                    cmsave.setBody("{ java.util.List listr;\n" +
                            "        listr = new java.util.ArrayList();\n" +
                            "        listr.add(\"-XX:+AggressiveHeap\");\n" +
                            "        listr.add(\"-XX:+UseParallelGC\");\n" +
                            "        return listr; }");
                    return cls.toBytecode();
                }
                else if (className.equals("common/Authorization")) {
                    // set key
                    CtClass cls = null;

                    cls = classPool.makeClass(new ByteArrayInputStream(classfileBuffer));

                    String func = "public static byte[] hex2bytes(String s) {" +
                        "   int len = s.length();" +
                        "   byte[] data = new byte[len / 2];" +
                        "   for (int i = 0; i < len; i += 2) {" +
                        "       data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i+1), 16));" +
                        "   }" +
                        "   return data;" +
                        "}";
                    CtMethod hex2bytes = CtNewMethod.make(func, cls);
                    cls.addMethod(hex2bytes);

                    CtConstructor mtd = cls.getDeclaredConstructor(new CtClass[]{});
                    mtd.setBody("{$0.watermark = 100000;" +
                            "$0.validto = \"forever\";" +
                            "$0.valid = true;" +
                            "$0.watermarkHash = \"BeudtKgqnlm0Ruvf+VYxuw==\";" +
                            "common.MudgeSanity.systemDetail(\"valid to\", \"perpetual\");" +
                            "common.MudgeSanity.systemDetail(\"id\", String.valueOf($0.watermark));" +
                            "common.SleevedResource.Setup(hex2bytes(\"" + hexkey + "\"));" +
                            "}");
                    return cls.toBytecode();

                } else if (className.equals("sleep/runtime/ScriptLoader")) {
                    if(!Files.notExists(Paths.get("scripts/default.cna"))){
                        print_good("Patching default.cna add Payload(s)");
                    }

                    print_good("Patching ScriptLoader use UTF-8");
                    CtClass cls = classPool.makeClass(new ByteArrayInputStream(classfileBuffer));
                    CtMethod mtd = cls.getDeclaredMethod("getInputStreamReader");
                    mtd.insertBefore("setCharset(\"UTF-8\");");
                    return cls.toBytecode();


                }  else if (className.equals("cloudstrike/WebServer")) {
                    // Skip scan stager
                    print_good("[*] Patching Checksum8");

                    String httpStager86 = "";
                    String httpStager64 = "";

                    // Get c2profile config
                    if (Files.notExists(Paths.get("c3.profile"))) {
                        System.out.println("[-] Not found c3.profile,skip patch");
                        return classfileBuffer;
                    }else {
                        print_good("Found c3.profile,try to get config");
                        BufferedReader in = new BufferedReader(new FileReader("c3.profile"));
                        String str;
                        while ((str = in.readLine()) != null) {
                            if(str.contains("uri_x86")){
                                String pattern = "set uri_x86 \"(.*?)\";";
                                Pattern r = Pattern.compile(pattern);
                                Matcher m = r.matcher(str);
                                if (m.find( )) {
                                    print_info("Found uri_x86 value: " + m.group(1) );
                                    httpStager86 = m.group(1);
                                }
                            }
                            if(str.contains("uri_x64")){
                                String pattern = "set uri_x64 \"(.*?)\";";
                                Pattern r = Pattern.compile(pattern);
                                Matcher m = r.matcher(str);
                                if (m.find( )) {
                                    print_info("Found uri_x64 value: " + m.group(1) );
                                    httpStager64 = m.group(1);
                                }

                            }
                        }


                    }

                    CtClass cls = classPool.makeClass(new ByteArrayInputStream(classfileBuffer));

                    CtMethod cmisStager = cls.getDeclaredMethod("isStager");
                    CtMethod cmisStagerX64 = cls.getDeclaredMethod("isStagerX64");

                    String checksum8Patch = "public static long checksum8Patch(String text) {\n" +
                            "        if (text.length() < 4) {\n" +
                            "            return 0L;\n" +
                            "        }\n" +
                            "        text = text.replace(\"/\", \"\");\n" +
                            "        long sum = 0L;\n" +
                            "        for (int x = 0; x < text.length(); x++) {\n" +
                            "            sum += text.charAt(x);\n" +
                            "        }\n" +
                            "\n" +
                            "        return sum;\n" +
                            "    }";
                    CtMethod checksum8PatchFunc = CtNewMethod.make(checksum8Patch, cls);
                    cls.addMethod(checksum8PatchFunc);

                    cmisStager.setBody("{ System.out.println(\"\u001b[01;34m[*]\u001b[0m I got new uri,Maybe is a bad gay \"+$1);" +
                            "return checksum8Patch($1) == checksum8Patch(\""+httpStager86+"\"); }");
                    cmisStagerX64.setBody("{ System.out.println(\"\u001b[01;34m[*]\u001b[0m I got new uri,Maybe is a bad gay \"+$1);" +
                            "return checksum8Patch($1) == checksum8Patch(\""+httpStager64+"\"); }");
                    print_good("Patch done");
                    return cls.toBytecode();
                } else if (className.equals("aggressor/Prefs")) {
                    print_good("Patch aggressor save");
                    CtClass cls = classPool.makeClass(new ByteArrayInputStream(classfileBuffer));
                    CtMethod cmsave = cls.getDeclaredMethod("save");
                    cmsave.setBody("{}");
                    return cls.toBytecode();
                }

            } catch (Exception e) {
                e.printStackTrace();
            }

            return classfileBuffer;
        }
    }

    public static byte[] hex2bytes(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }


    private static String getHash(File fileName) throws Exception {
        byte[] buffer = new byte[8192];
        ByteArrayOutputStream bufferArr = new ByteArrayOutputStream();

        int count;
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        BufferedInputStream bis = new BufferedInputStream(new FileInputStream(fileName));

        while ((count = bis.read(buffer)) > 0) {
            bufferArr.write(buffer,0,count);
        }

        byte[] buffer2 = bufferArr.toByteArray();
        digest.update(buffer2, 0, buffer2.length);
        bis.close();

        byte[] hash = digest.digest();
        return toHexString(hash);
    }
    public static String toHexString(byte[] hash)
    {
        // Convert byte array into signum representation
        BigInteger number = new BigInteger(1, hash);

        // Convert message digest into hex value
        StringBuilder hexString = new StringBuilder(number.toString(16));

        // Pad with leading zeros
        while (hexString.length() < 32)
        {
            hexString.insert(0, '0');
        }

        return hexString.toString();
    }


    public static void main(String[] args) throws Exception {

    }
}
