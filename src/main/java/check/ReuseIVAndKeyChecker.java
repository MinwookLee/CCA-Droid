package check;

import model.Line;
import model.SlicingCriterion;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;

public class ReuseIVAndKeyChecker extends BaseChecker {

    public ReuseIVAndKeyChecker() {
        checkerName = getClass().getName();
    }

    @Override
    public ArrayList<SlicingCriterion> getSlicingCandidates() {
        ArrayList<SlicingCriterion> list = new ArrayList<>();

        /* javax.crypto.Cipher - init() */

        SlicingCriterion criterion1 = new SlicingCriterion();
        criterion1.setTargetStatement1("<javax.crypto.Cipher: void init(int,java.security.Key,java.security.AlgorithmParameters)>");
        criterion1.setTargetParamNums("-1");
        list.add(criterion1);

        SlicingCriterion criterion2 = new SlicingCriterion();
        criterion2.setTargetStatement1("<javax.crypto.Cipher: void init(int,java.security.Key,java.security.spec.AlgorithmParameterSpec)>");
        criterion2.setTargetParamNums("-1");
        list.add(criterion2);

        SlicingCriterion criterion3 = new SlicingCriterion();
        criterion3.setTargetStatement1("<javax.crypto.Cipher: void init(int,java.security.Key,java.security.spec.AlgorithmParameterSpec,java.security.SecureRandom)>");
        criterion3.setTargetParamNums("-1");
        list.add(criterion3);

        SlicingCriterion criterion4 = new SlicingCriterion();
        criterion4.setTargetStatement1("<javax.crypto.Cipher: void init(int,java.security.Key,java.security.AlgorithmParameters,java.security.SecureRandom)>");
        criterion4.setTargetParamNums("-1");
        list.add(criterion4);

        return list;
    }

    @Override
    public void checkRule(SlicingCriterion slicingCriterion, HashMap<String, ArrayList<ArrayList<Line>>> slicesMap) {
        ArrayList<ArrayList<Line>> slices1 = slicesMap.get("-1");
        if (slices1.isEmpty()) {
            return;
        }

        ArrayList<ArrayList<Line>> keySlices = new ArrayList<>();
        ArrayList<ArrayList<Line>> ivSlices = new ArrayList<>();
        for (ArrayList<Line> s : slices1) {
            int sliceLength = s.size();
            Line lastLine = s.get(sliceLength - 1);
            String callerName = lastLine.getCallerName();
            keySlices = findKeySlices(callerName);
            ivSlices = findIVSlices(callerName);
            if (!keySlices.isEmpty() && !ivSlices.isEmpty()) {
                break;
            }
        }

        if (keySlices.isEmpty() || ivSlices.isEmpty()) {
            return;
        }

        for (ArrayList<Line> s2 : keySlices) {
            ArrayList<Line> randomLines1 = findRandomLines(s2);
            ArrayList<Line> constantLines1 = findConstantLines(s2, "^((?!(?i)(DES|AES|RSA|HMAC)|[0-9]+).)*$", true);
            if (randomLines1.isEmpty() && constantLines1.isEmpty()) {
                continue;
            }

            for (ArrayList<Line> s3 : ivSlices) {
                ArrayList<Line> randomLines2 = findRandomLines(s3);
                ArrayList<Line> constantLines2 = findConstantLines(s3, "^((?!(?i)(DES|AES|RSA|HMAC)|[0-9]+).)*$", true);
                if (randomLines2.isEmpty() && constantLines2.isEmpty()) {
                    continue;
                }

                ArrayList<Line> targetLines = new ArrayList<>();
                if (randomLines1.isEmpty() && !constantLines1.isEmpty() && randomLines2.isEmpty() && !constantLines2.isEmpty()) {
                    targetLines.addAll(constantLines1);
                    targetLines.addAll(constantLines2);
                    printResult(slicingCriterion, targetLines, true);
                } else {
                    targetLines.addAll(randomLines1);
                    targetLines.addAll(randomLines2);
                    printResult(slicingCriterion, targetLines, false);
                }
            }
        }
    }

    private ArrayList<ArrayList<Line>> findKeySlices(String callerName) {
        ArrayList<String> targetSignatures = new ArrayList<>();
        targetSignatures.add("<javax.crypto.spec.PBEKeySpec: void <init>(char[])>");
        targetSignatures.add("<javax.crypto.spec.PBEKeySpec: void <init>(char[],byte[],int)>");
        targetSignatures.add("<javax.crypto.spec.PBEKeySpec: void <init>(char[],byte[],int,int)>");
        targetSignatures.add("<javax.crypto.spec.DESKeySpec: void <init>(byte[])>");
        targetSignatures.add("<javax.crypto.spec.DESKeySpec: void <init>(byte[],int)>");
        targetSignatures.add("<javax.crypto.spec.SecretKeySpec: void <init>(byte[],java.lang.String)>");
        targetSignatures.add("<javax.crypto.spec.SecretKeySpec: void <init>(byte[],int,int,java.lang.String)>");

        ArrayList<ArrayList<Line>> targetSlices = new ArrayList<>();
        for (String t : targetSignatures) {
            ArrayList<ArrayList<Line>> slices = sliceMerger.findSlices(t);
            for (ArrayList<Line> s : slices) {
                int sliceLength = s.size();
                Line lastLine = s.get(sliceLength - 1);
                String targetCallerName = lastLine.getCallerName();
                if (targetCallerName.equals(callerName)) {
                    targetSlices.add(s);
                }
            }
        }

        return targetSlices;
    }

    private ArrayList<ArrayList<Line>> findIVSlices(String callerName) {
        ArrayList<String> targetSignatures = new ArrayList<>();
        targetSignatures.add("<javax.crypto.spec.IvParameterSpec: void <init>(byte[])>");
        targetSignatures.add("<javax.crypto.spec.IvParameterSpec: void <init>(byte[],int,int)>");
        targetSignatures.add("<javax.crypto.spec.GCMParameterSpec: void <init>(int,byte[])>");
        targetSignatures.add("<javax.crypto.spec.GCMParameterSpec: void <init>(int,byte[],int,int)>");

        ArrayList<ArrayList<Line>> targetSlices = new ArrayList<>();
        for (String t : targetSignatures) {
            ArrayList<ArrayList<Line>> slices = sliceMerger.findSlices(t);
            for (ArrayList<Line> s : slices) {
                int sliceLength = s.size();
                Line lastLine = s.get(sliceLength - 1);
                String targetCallerName = lastLine.getCallerName();
                if (targetCallerName.equals(callerName)) {
                    targetSlices.add(s);
                }
            }
        }

        return targetSlices;
    }

    private ArrayList<Line> findRandomLines(ArrayList<Line> slice) {
        ArrayList<String> targetSignatures = new ArrayList<>();
        targetSignatures.add("<java.util.Random: void nextBytes(byte[])>");
        targetSignatures.add("<java.util.Random: int nextInt()>");
        targetSignatures.add("<java.security.SecureRandom: void nextBytes(byte[])>");
        targetSignatures.add("<java.security.SecureRandom: int nextInt()>");
        targetSignatures.add("<javax.crypto.KeyGenerator: javax.crypto.SecretKey generateKey()>");

        return findTargetSignatureLines(slice, targetSignatures);
    }

    private void printResult(SlicingCriterion slicingCriterion, ArrayList<Line> targetLines, boolean hasVulnerable) {
        if (targetLines.isEmpty()) {
            return;
        }

        LinkedHashSet<Line> tempLines = new LinkedHashSet<>(targetLines);
        if (isDuplicateLines(checkerName, tempLines)) {
            return;
        }

        String ruleId;
        String ruleDescription;
        if (hasVulnerable) {
            ruleId = "10";
            ruleDescription = "This slice uses a reused Key and IV pairs";
        } else {
            ruleId = "10-2";
            ruleDescription = "This slice uses a not reused Key and IV pairs";
        }

        printResult(ruleId, ruleDescription, slicingCriterion, null, tempLines);
    }
}