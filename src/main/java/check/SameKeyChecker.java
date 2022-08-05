package check;

import model.Line;
import model.SlicingCriterion;
import soot.Unit;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;

import static utils.SootUnit.*;

public class SameKeyChecker extends BaseChecker {

    public SameKeyChecker() {
        checkerName = getClass().getName();
    }

    @Override
    public ArrayList<SlicingCriterion> getSlicingCandidates() {
        ArrayList<SlicingCriterion> list = new ArrayList<>();

        /* javax.crypto.Mac - init() */

        SlicingCriterion criterion1 = new SlicingCriterion();
        criterion1.setTargetStatement1("<javax.crypto.Mac: void init(java.security.Key)>");
        criterion1.setTargetParamNums("0");
        list.add(criterion1);

        SlicingCriterion criterion2 = new SlicingCriterion();
        criterion2.setTargetStatement1("<javax.crypto.Mac: void init(java.security.Key,java.security.spec.AlgorithmParameterSpec)>");
        criterion2.setTargetParamNums("0");
        list.add(criterion2);

        return list;
    }

    @Override
    public void checkRule(SlicingCriterion slicingCriterion, HashMap<String, ArrayList<ArrayList<Line>>> slicesMap) {
        ArrayList<ArrayList<Line>> slices = slicesMap.get("0"); // To use this rule, any checker contains cipher.init() is required!
        for (ArrayList<Line> s : slices) {
            if (s.isEmpty()) {
                continue;
            }

            ArrayList<Line> cipherSlice1 = findCipherSlice1(s);
            ArrayList<Line> cipherSlice2 = findCipherSlice2(s);
            ArrayList<Line> cipherSlice = (cipherSlice1 == null) ? cipherSlice2 : cipherSlice1;
            if (cipherSlice == null) {
                continue;
            }

            HashSet<Line> set1 = new HashSet<>(s);
            HashSet<Line> set2 = new HashSet<>(cipherSlice);
            set1.retainAll(set2);

            Line cipherKeyLine = findKeyLine(cipherSlice);
            if (cipherKeyLine == null) {
                continue;
            }

            Line macKeyLine = findKeyLine(s);
            if (macKeyLine == null) {
                continue;
            }

            ArrayList<Line> targetLines = new ArrayList<>();
            targetLines.add(cipherKeyLine);
            targetLines.add(macKeyLine);

            boolean hasVulnerable = !set1.isEmpty();
            printResult(slicingCriterion, targetLines, hasVulnerable);
        }
    }

    private ArrayList<Line> findCipherSlice1(ArrayList<Line> slice) {
        ArrayList<String> targetSignatures = new ArrayList<>();
        targetSignatures.add("<javax.crypto.Cipher: void init(int,java.security.Key)>");
        targetSignatures.add("<javax.crypto.Cipher: void init(int,java.security.Key,java.security.spec.AlgorithmParameterSpec)>");

        ArrayList<Line> targetLines = findSignatures(slice, targetSignatures);
        if (!targetLines.isEmpty()) {
            return slice;
        }

        ArrayList<Line> cipherSlice = null;
        int sliceSize = slice.size();
        for (int i = sliceSize - 1; i > -1; i--) {
            Line line = slice.get(i);
            int unitType = line.getUnitType();
            if ((unitType & INVOKE) != INVOKE) {
                continue;
            }

            Unit unit = line.getUnit();
            String signature = getSignature(unit);
            ArrayList<ArrayList<Line>> slices = findAssignInvokeSlices(signature);
            for (ArrayList<Line> s : slices) {
                targetLines = findTargetSignatureLines(s, targetSignatures);
                if (targetLines.isEmpty()) {
                    continue;
                }

                cipherSlice.addAll(s);
                break;
            }

            if (cipherSlice != null) {
                break;
            }
        }

        return cipherSlice;
    }

    private ArrayList<Line> findCipherSlice2(ArrayList<Line> slice) {
        ArrayList<String> targetSignatures = new ArrayList<>();
        targetSignatures.add("<javax.crypto.Cipher: void init(int,java.security.Key)>");
        targetSignatures.add("<javax.crypto.Cipher: void init(int,java.security.Key,java.security.spec.AlgorithmParameterSpec)>");

        Line lastLine1 = slice.get(slice.size() - 1);
        String callerName1 = lastLine1.getCallerName();

        ArrayList<Line> cipherSlice = null;
        for (String t : targetSignatures) {
            ArrayList<ArrayList<Line>> slices = slicer.findSlices(t, slice);
            for (ArrayList<Line> s : slices) {
                Line lastLine2 = slice.get(slice.size() - 1);
                String callerName2 = lastLine2.getCallerName();
                if (callerName1.equals(callerName2)) {
                    cipherSlice = s;
                    break;
                }
            }
        }

        return cipherSlice;
    }

    private Line findKeyLine(ArrayList<Line> slice) {
        Line targetLine = null;

        for (Line l : slice) {
            Unit unit = l.getUnit();
            int unitType = l.getUnitType();

            if ((unitType & INVOKE) == INVOKE) {
                String signature = getSignature(unit);
                String className = getClassName(signature);
                String returnType = getReturnType(signature);
                if ((className.endsWith("KeySpec") && returnType.equals("void")) || (returnType.equals("javax.crypto.SecretKey"))) {
                    targetLine = l;
                }
            } else if (unitType == ASSIGN_VARIABLE_SIGNATURE) {
                String signature = getSignature(unit);
                String returnType = getReturnType(signature);
                if (returnType.equals("javax.crypto.SecretKey") || returnType.endsWith("KeySpec")) {
                    targetLine = l;
                }
            }

            if (targetLine != null) {
                break;
            }
        }

        return targetLine;
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
            ruleId = "15";
            ruleDescription = "This slice uses same key for Encrypt-then-MAC";
        } else {
            ruleId = "15-2";
            ruleDescription = "This slice uses different keys for Encrypt-then-MAC";
        }

        HashMap<String, Object> result = new HashMap<>();
        printResult(ruleId, ruleDescription, slicingCriterion, result, tempLines);
    }
}