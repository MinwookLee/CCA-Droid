package main;

import analyze.ApkParser;
import analyze.CodeInspector;
import check.BaseChecker;
import model.Line;
import model.SlicingCriterion;
import slice.ProgramSlicer;
import slice.SliceMerger;
import slice.SlicingCriteriaGenerator;

import java.util.ArrayList;
import java.util.HashMap;

import static java.lang.Runtime.getRuntime;
import static utils.Soot.initialize;
import static utils.Soot.loadDexClasses;

public class EngineMain {

    public static void main(String[] args) {
        if (args.length == 0) {
            System.out.println("[*] ERROR : No file path to be analyzed was entered!");
            System.exit(1);
        }

        String apkPath = args[0];
        ApkParser apkParser = ApkParser.getInstance();
        apkParser.initialize(apkPath);
        apkParser.parseManifest();

        String packageName = apkParser.getPackageName();
        System.out.println("[*] Analyzing APK : " + apkPath);
        System.out.println("[*] Base package : " + packageName);

        Configuration configuration = Configuration.getInstance();
        configuration.setArguments(args);
        configuration.loadRuleCheckers();

        initialize(apkPath);
        loadDexClasses();

        CodeInspector codeInspector = CodeInspector.getInstance();
        codeInspector.buildCallGraph();

        SlicingCriteriaGenerator slicingCriteriaGenerator = SlicingCriteriaGenerator.getInstance();
        ProgramSlicer slicer = ProgramSlicer.getInstance();
        SliceMerger sliceMerger = SliceMerger.getInstance();

        ArrayList<BaseChecker> ruleCheckers = configuration.getRuleCheckers();
        for (BaseChecker checker : ruleCheckers) {
            ArrayList<SlicingCriterion> candidates = checker.getSlicingCandidates();
            ArrayList<SlicingCriterion> slicingCriteria = slicingCriteriaGenerator.createSlicingCriteria(candidates);
            for (SlicingCriterion sc1 : slicingCriteria) {
                HashMap<String, ArrayList<ArrayList<Line>>> slicesMap = new HashMap<>();

                ArrayList<SlicingCriterion> splitted = slicingCriteriaGenerator.splitSlicingCriterion(sc1);
                for (SlicingCriterion sc2: splitted) {
                    slicer.runWhileQueueIsNotEmpty(sc2);
                    
                    String targetParamNum = sc2.getTargetParamNum();
                    ArrayList<ArrayList<Line>> slices = sliceMerger.createSlices(sc2);
                    slicesMap.put(targetParamNum, slices);
                }

                checker.checkRule(sc1, slicesMap);
            }
        }

        printExecutionInfo();
    }

    private static void printExecutionInfo() {
        SlicingCriteriaGenerator slicingCriteriaMaker = SlicingCriteriaGenerator.getInstance();
        SliceMerger sliceMerger = SliceMerger.getInstance();

        Configuration configuration = Configuration.getInstance();
        String upperLevel = configuration.getConfig("upperLevel");
        String lowerLevel = configuration.getConfig("lowerLevel");

        long megabytes = 1024L * 1024L;
        Runtime runtime = getRuntime();
        long totalMemory = runtime.totalMemory() / megabytes;
        long freeMemory = runtime.freeMemory() / megabytes;
        long usedMemory = totalMemory - freeMemory;

        System.out.println("[*] Print execution info:");
        System.out.println("Criteria count : " + slicingCriteriaMaker.getCriteriaCount());
        System.out.println("Slices count : " + sliceMerger.getSliceCount());
        System.out.println("Depth range : " + lowerLevel + " ~ +" + upperLevel);
        System.out.println("totalMemory : " + totalMemory);
        System.out.println("freeMemory : " + freeMemory);
        System.out.println("usedMemory : " + usedMemory);
    }
}