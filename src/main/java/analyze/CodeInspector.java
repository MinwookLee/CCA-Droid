package analyze;

import graph.CallGraph;
import org.graphstream.graph.Node;
import soot.*;
import soot.jimple.*;
import soot.tagkit.ConstantValueTag;
import soot.tagkit.Tag;
import soot.toolkits.graph.ExceptionalUnitGraph;
import soot.toolkits.graph.UnitGraph;
import soot.util.Chain;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static graph.BaseGraph.EdgeType.*;
import static java.lang.Double.parseDouble;
import static java.lang.Float.parseFloat;
import static java.lang.Integer.parseInt;
import static java.lang.Long.parseLong;
import static java.util.regex.Pattern.compile;
import static utils.SootUnit.*;

public class CodeInspector {
    private final CallGraph callGraph;
    private final HashMap<String, SootMethod> sootMethodMap;
    private final HashMap<String, Value> constantValueMap;

    private CodeInspector() {
        callGraph = new CallGraph();
        sootMethodMap = new HashMap<>();
        constantValueMap = new HashMap<>();
    }

    public static CodeInspector getInstance() {
        return CodeInspector.Holder.instance;
    }

    public void buildCallGraph() {
        String excludeRegex = "^(dalvik|android|kotlin|io.flutter|scala).*$";
        Pattern pattern = compile(excludeRegex);

        ApkParser apkParser = ApkParser.getInstance();
        ArrayList<String> targetClassNames = apkParser.getDexClassNames();
        for (String name : targetClassNames) {
            Matcher matcher = pattern.matcher(name);
            if (matcher.matches()) {
                continue;
            }

            SootClass sootClass = Scene.v().getSootClass(name);
            List<SootMethod> sootMethods = sootClass.getMethods();
            ArrayList<SootMethod> tempMethods = new ArrayList<>(sootMethods); // avoid java.util.ConcurrentModificationException
            for (SootMethod m : tempMethods) {
                if (!m.isConcrete()) {
                    continue;
                }

                boolean isStaticInitializer = m.isStaticInitializer();
                if (isStaticInitializer) { // for only static initializer
                    parseStaticFinalValue(sootClass);
                }

                try {
                    String callerName = m.toString();
                    sootMethodMap.put(callerName, m);

                    Node caller = callGraph.addNode(callerName, callerName, null);
                    Body body = m.retrieveActiveBody();

                    UnitGraph unitGraph = new ExceptionalUnitGraph(body);
                    for (Unit u : unitGraph) {
                        int unitType = getUnitType(u);
                        if (unitType == -1) {
                            continue;
                        }

                        switch (unitType) {
                            case ASSIGN_VIRTUAL_INVOKE:
                            case ASSIGN_STATIC_INVOKE:
                            case ASSIGN_INTERFACE_INVOKE:
                            case ASSIGN_SPECIAL_INVOKE:
                            case VIRTUAL_INVOKE:
                            case STATIC_INVOKE:
                            case INTERFACE_INVOKE:
                            case SPECIAL_INVOKE: {
                                String calleeName = getSignature(u);
                                Node callee = callGraph.addNode(calleeName, calleeName, null);
                                callGraph.addEdge(caller, callee, DOWNWARD);
                                break;
                            }

                            case ASSIGN_SIGNATURE_CONSTANT: {
                                String signature = getSignature(u);
                                Value value;

                                if (!constantValueMap.containsKey(signature)) {
                                    String valueStr = getRightValueStr(u, unitType);
                                    valueStr = valueStr.replace("\"", "");
                                    value = convertStringToValue(signature, valueStr);
                                } else {
                                     value = getLeftValue(u, unitType);
                                }

                                constantValueMap.put(signature, value);
                                break;
                            }

                            case ASSIGN_VARIABLE_SIGNATURE:
                            case ASSIGN_SIGNATURE_VARIABLE: {
                                String signature = getSignature(u);
                                String className = getClassName(signature);
                                if (!targetClassNames.contains(className)) {
                                    break;
                                }

                                Node callee = callGraph.addNode(signature, signature, null);
                                if (unitType == ASSIGN_VARIABLE_SIGNATURE) {
                                    callGraph.addEdge(caller, callee, READ);
                                } else {
                                    constantValueMap.remove(signature);
                                    callGraph.addEdge(caller, callee, WRITE);
                                }

                                break;
                            }
                        }
                    }
                } catch (RuntimeException | StackOverflowError | OutOfMemoryError ignored) { // for Soot internal error

                }
            }
        }
    }

    public Node getNode(String signature) {
        return callGraph.getNode(signature);
    }

    public Value getConstantValue(String signature) {
        return constantValueMap.get(signature);
    }

    public SootMethod getSootMethod(String signature) {
        return sootMethodMap.get(signature);
    }

    public ArrayList<ArrayList<String>> traverseCallers(String signature, boolean upper) {
        return callGraph.getListOfIds(signature, upper);
    }

    private static class Holder {
        private static final CodeInspector instance = new CodeInspector();
    }

    private void parseStaticFinalValue(SootClass sootClass) {
        Chain<SootField> fields = sootClass.getFields();
        for (SootField f : fields) {
            if (!f.isStatic() || !f.isFinal()) {
                continue;
            }

            List<Tag> tags = f.getTags();
            if (tags.isEmpty()) {
                continue;
            }

            Tag tag = tags.get(0);
            if (!(tag instanceof ConstantValueTag)) {
                continue;
            }

            String key = f.getSignature();
            String tagStr = tag.toString();
            String[] strArr = tagStr.split("ConstantValue: ");
            int length = strArr.length;
            if (length > 1) {
                Value value = convertStringToValue(key, strArr[1]);
                constantValueMap.putIfAbsent(key, value);
            } else {
                constantValueMap.putIfAbsent(key, StringConstant.v("")); // this is <className: String variableName> = ""
            }
        }
    }

    private Value convertStringToValue(String signature, String valueStr) {
        if (valueStr.equals("null")) {
            return NullConstant.v();
        }

        Value value;
        String returnType = getReturnType(signature);
        switch (returnType) {
            case "boolean":
            case "short":
            case "int": {
                value = IntConstant.v(parseInt(valueStr));
                break;
            }

            case "double": {
                if (valueStr.contains("NaN")) {
                    value = DoubleConstant.v(Double.NaN);
                } else if (valueStr.contains("Infinity")) {
                    value = (valueStr.contains("-")) ? DoubleConstant.v(Double.NEGATIVE_INFINITY) : DoubleConstant.v(Double.POSITIVE_INFINITY);
                } else {
                    value = DoubleConstant.v(parseDouble(valueStr));
                }

                break;
            }

            case "long": {
                valueStr = valueStr.replace("L", "");
                value = LongConstant.v(parseLong(valueStr));
                break;
            }

            case "float": {
                valueStr = valueStr.replace("F", "");
                if (valueStr.contains("NaN")) {
                    value = FloatConstant.v(Float.NaN);
                } else if (valueStr.contains("Infinity")) {
                    value = (valueStr.contains("-")) ? FloatConstant.v(Float.NEGATIVE_INFINITY) : FloatConstant.v(Float.POSITIVE_INFINITY);
                } else {
                    value = FloatConstant.v(parseFloat(valueStr));
                }

                break;
            }

            default: { // char, byte, java.lang.String
                valueStr = valueStr.replace("\"", "");
                value = StringConstant.v(valueStr);
                break;
            }
        }

        return value;
    }
}