package slice;

import analyze.ApkParser;
import graph.BaseGraph;
import graph.CallGraph;
import model.Line;
import model.SlicingCriterion;
import org.graphstream.graph.Node;
import soot.Unit;

import java.util.*;

import static graph.BaseGraph.EdgeType.DOWNWARD;
import static graph.BaseGraph.EdgeType.UPWARD;
import static java.lang.Integer.parseInt;
import static java.lang.String.valueOf;
import static utils.SootUnit.*;

public class SliceMerger {
    private final CallGraph callGraph;
    private final SliceOptimizer sliceOptimizer;
    private final ConstraintSolver constraintSolver;
    public final HashMap<String, ArrayList<ArrayList<Line>>> slicesMap;
    private int sliceCount;

    public SliceMerger() {
        callGraph = new CallGraph();
        sliceOptimizer = SliceOptimizer.getInstance();
        constraintSolver = ConstraintSolver.getInstance();
        slicesMap = new HashMap<>();
        sliceCount = 0;
    }

    public static SliceMerger getInstance() {
        return SliceMerger.Holder.instance;
    }

    public Node addNode(String hashCode, String label, String values) {
        Node node = callGraph.addNode(hashCode, label, values);
        node.setAttribute("level", 0);

        return node;
    }

    public Node getNode(String hashCode) {
        return callGraph.getNode(hashCode);
    }

    public void addEdge(Node node1, Node node2, BaseGraph.EdgeType type) {
        int level = parseInt(valueOf(node1.getAttribute("level")));
        if (type == null) {
            node2.setAttribute("level", level);
            callGraph.addEdge(node1, node2, type);
        } else if (type == UPWARD) {
            node2.setAttribute("level", level + 1);
            callGraph.addEdge(node2, node1, type);
        } else if (type == DOWNWARD) {
            node2.setAttribute("level", level - 1);
            callGraph.addEdge(node1, node2, type);
        }
    }

    public ArrayList<ArrayList<Line>> createSlices(SlicingCriterion slicingCriterion) {
        String targetHashCode = String.valueOf(slicingCriterion.hashCode());
        return createSlices(targetHashCode);
    }

    public ArrayList<ArrayList<Line>> createSlices(String targetHashCode) {
        ArrayList<ArrayList<Line>> slices = slicesMap.get(targetHashCode);
        if (slices != null) {
            return slices;
        }

        slices = new ArrayList<>();
        ArrayList<ArrayList<String>> listOfHashCodes = getListOfHashCodes(targetHashCode);
        for (ArrayList<String> hashCodes : listOfHashCodes) {
            ArrayList<Line> slice = mergeSlice(hashCodes);
            if (slice.isEmpty()) {
                continue;
            }

            if (startParameterUnit(slice)) {
                continue;
            }

            if (!isReachableSlice(slice)) {
                continue;
            }

            if(isContainedSlice(slice, slices)) {
                continue;
            }

            removeInfesibleLines(slice);
            if (slice.isEmpty()) {
                continue;
            }

            System.out.println("final slice:");
            for (Line l : slice) {
                System.out.println(l);
            }

            System.out.println();

            slices.add(slice);
        }

        slicesMap.put(targetHashCode, slices);
        sliceCount += slices.size();

        return slices;
    }

    public ArrayList<ArrayList<Line>> findSlices(String targetSignature) {
        ArrayList<ArrayList<Line>> targetSlices = new ArrayList<>();

        Collection<ArrayList<ArrayList<Line>>> slices = slicesMap.values();
        for (ArrayList<ArrayList<Line>> s : slices) {
            for (ArrayList<Line> s2: s) {
                for (Line l : s2) {
                    int unitType = l.getUnitType();
                    if ((unitType & INVOKE) != INVOKE) {
                        continue;
                    }

                    Unit unit = l.getUnit();
                    String signature = getSignature(unit);
                    if (!signature.equals(targetSignature)) {
                        continue;
                    }

                    targetSlices.add(s2);
                }
            }
        }

        return targetSlices;
    }

    public int getSliceCount() {
        return sliceCount;
    }

    private static class Holder {
        private static final SliceMerger instance = new SliceMerger();
    }

    private ArrayList<ArrayList<String>> getListOfHashCodes(String hashCode) {
        return callGraph.getListOfIds(hashCode, true);
    }

    private ArrayList<Line> mergeSlice(ArrayList<String> hashCodes) {
        SlicingCriteriaGenerator slicingCriteriaGenerator = SlicingCriteriaGenerator.getInstance();
        ProgramSlicer slicer = ProgramSlicer.getInstance();

        ArrayList<Line> slice = new ArrayList<>();

        int hashCodeCount = hashCodes.size();
        for (int i = hashCodeCount - 1; i > -1; i--) {
            String hashCode = hashCodes.get(i);
            SortedSet<Line> tempSlice = new TreeSet<>();

            SlicingCriterion slicingCriterion = slicingCriteriaGenerator.getSlicingCriterion(hashCode);
            if (slicingCriterion == null) { // for assign variable signature
                continue;
            }

            ArrayList<String> targetVariables = slicingCriterion.getTargetVariables();
            for (String v : targetVariables) {
                ArrayList<String> tempVariables = new ArrayList<>();
                tempVariables.add(v);

                SlicingCriterion tempCriterion = (SlicingCriterion) slicingCriterion.clone();
                tempCriterion.setTargetVariables(tempVariables);

                String targetHashCode = String.valueOf(tempCriterion.hashCode());
                ArrayList<Line> targetSlice = slicer.getSlice(targetHashCode);
                if (targetSlice == null) {
                    continue;
                }

                tempSlice.addAll(targetSlice);
            }

            if (tempSlice.isEmpty()) {
                continue;
            }

            slice.addAll(0, tempSlice);
        }

        return slice;
    }

    private boolean startParameterUnit(ArrayList<Line> slice) {
        Line topLine = slice.get(0);
        int topUnitType = topLine.getUnitType();

        return (topUnitType == PARAMETER);
    }

    private boolean isReachableSlice(ArrayList<Line> slice) {
        Line firstLine = slice.get(0);
        String callerName = firstLine.getCallerName();
        ApkParser apkParser = ApkParser.getInstance();
        String packageName = apkParser.getPackageName();

        HashSet<String> set1 = new HashSet<>(List.of(packageName.split("\\.")));
        HashSet<String> set2 = new HashSet<>(List.of(callerName.split("\\.")));
        set2.retainAll(set1);

        return !set2.isEmpty();
    }

    private boolean isContainedSlice(ArrayList<Line> slice, ArrayList<ArrayList<Line>> slices) {
        boolean flag = false;
        for (ArrayList<Line> s : slices) {
            if (!s.containsAll(slice)) {
                continue;
            }

            flag = true;
        }

        return flag;
    }

    private void removeInfesibleLines(ArrayList<Line> slice) {
        LinkedHashMap<String, ArrayList<Unit>> targetUnitsMap = new LinkedHashMap<>();

        for (Line l : slice) {
            String callerName = l.getCallerName();
            ArrayList<Unit> targetUnits = targetUnitsMap.get(callerName);
            if (targetUnits == null) {
                targetUnits = new ArrayList<>();
            }

            Unit unit = l.getUnit();
            targetUnits.add(unit);

            targetUnitsMap.put(callerName, targetUnits);
        }

        ArrayList<Unit> infeasibleUnits = new ArrayList<>();
        infeasibleUnits.addAll(sliceOptimizer.findInfeasibleUnits(targetUnitsMap));
        infeasibleUnits.addAll(constraintSolver.findInfeasibleUnits(targetUnitsMap));
        ArrayList<Line> tempSlice = new ArrayList<>(slice);
        for (Line l : tempSlice) {
            Unit unit = l.getUnit();
            if (!infeasibleUnits.contains(unit)) {
                continue;
            }

            slice.remove(l);

            String callerName = l.getCallerName();
            ArrayList<Unit> targetUnits = targetUnitsMap.get(callerName);
            Unit lastUnit = targetUnits.get(targetUnits.size() - 1);
            if (unit.equals(lastUnit)) {
                slice.clear();
            }
        }
    }
}