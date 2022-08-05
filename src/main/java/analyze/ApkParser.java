package analyze;

import net.dongliu.apk.parser.ApkFile;
import net.dongliu.apk.parser.bean.DexClass;
import org.w3c.dom.*;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.File;
import java.io.IOException;
import java.io.StringReader;
import java.util.ArrayList;

public class ApkParser {
    private ApkFile apkFile;
    private final ArrayList<String> dexClassNames;
    private String packageName;
    private String applicationClassName;
    private final ArrayList<String> androidComponents;

    private ApkParser() {
        androidComponents = new ArrayList<>();
        dexClassNames = new ArrayList<>();
    }

    public static ApkParser getInstance() {
        return Holder.instance;
    }

    public void initialize(String apkPath) {
        try {
            File file = new File(apkPath);
            apkFile = new ApkFile(file);
        } catch (IOException e) {
            System.out.println("[*] ERROR : '" + apkPath + "' does not exist!");
            System.exit(1);
        }
    }

    public void parseManifest() {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();
            String manifestXml = apkFile.getManifestXml();
            Document document = builder.parse(new InputSource(new StringReader(manifestXml)));
            Element root = document.getDocumentElement();

            packageName = root.getAttribute("package");

            NodeList childNodes = root.getChildNodes();
            int length = childNodes.getLength();
            Node applicationNode = null;
            for (int i = 1; i < length; i++) {
                Node node = childNodes.item(i);
                String nodeName = node.getNodeName();
                if (nodeName.equals("application")) {
                    applicationNode = node;
                    break;
                }
            }

            if (applicationNode == null) {
                return;
            }

            NamedNodeMap nodeMap = applicationNode.getAttributes();
            Node node = nodeMap.getNamedItem("android:name");
            if (node != null) {
                applicationClassName = applicationNode.getNodeValue();
            }

            childNodes = applicationNode.getChildNodes();
            length = childNodes.getLength();
            for (int i = 1; i < length; i++) {
                node = childNodes.item(i);
                if (nodeMap == null) {
                    continue;
                }

                String nodeName = node.getNodeName();
                if (!nodeName.equals("activity") && !nodeName.equals("service") && !nodeName.equals("provider") && !nodeName.equals("receiver")) {
                    continue;
                }

                node = nodeMap.getNamedItem("android:name");
                if (node == null) {
                    continue;
                }

                String nodeValue = node.getNodeValue();
                if (nodeValue.startsWith("android") || nodeValue.startsWith("kotlin") || nodeValue.startsWith("com.google")) {
                    continue;
                }

                androidComponents.add(nodeValue);
            }
        } catch (IOException | ParserConfigurationException | SAXException e) {
            System.out.println("[*] ERROR : Cannot parse AndroidManifest.xml of this apk!");
            System.exit(1);
        }
    }

    public String getPackageName() {
        return packageName;
    }

    public String getApplicationClassName() {
        return applicationClassName;
    }

    public ArrayList<String> getAndroidComponents() {
        return androidComponents;
    }

    public ArrayList<String> getDexClassNames() {
        if (!dexClassNames.isEmpty()) {
            return dexClassNames;
        }

        try {
            DexClass[] classes = apkFile.getDexClasses();
            for (DexClass c : classes) {
                String classType = c.getClassType();
                String className = classType.replace('/', '.');
                className = className.substring(1, className.length() - 1);

                dexClassNames.add(className);
            }
        } catch (IOException e) {
            System.out.println("[*] ERROR : Cannot get class names!");
        }

        return dexClassNames;
    }

    private static class Holder {
        private static final ApkParser instance = new ApkParser();
    }
}