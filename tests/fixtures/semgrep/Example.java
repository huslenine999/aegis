import java.beans.XMLDecoder;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.Statement;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;
import javax.net.ssl.X509TrustManager;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

public class Example {
    void find(Connection connection, Statement statement, String name) throws Exception {
        // ruleid: java-sql-injection
        statement.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
        // ruleid: java-sql-injection
        connection.prepareStatement(String.format("SELECT * FROM users WHERE name = '%s'", name));
        // ok: java-sql-injection
        PreparedStatement prepared = connection.prepareStatement("SELECT * FROM users WHERE name = ?");
        prepared.setString(1, name);
    }

    void run(String host) throws Exception {
        // ruleid: java-command-injection
        Runtime.getRuntime().exec("ping -c 1 " + host);
        // ruleid: java-command-injection
        new ProcessBuilder("sh", "-c", host).start();
        // ok: java-command-injection
        new ProcessBuilder("ping", "-c", "1", host).start();
        // ok: java-command-injection
        Runtime.getRuntime().exec("uptime");
    }

    Object read(InputStream input) throws Exception {
        ObjectInputStream objects = new ObjectInputStream(input);
        // ruleid: java-unsafe-deserialization
        return objects.readObject();
    }

    Object readXml(InputStream input) {
        // ruleid: java-unsafe-deserialization
        return new XMLDecoder(input).readObject();
    }

    DocumentBuilder unsafeParser() throws Exception {
        // ruleid: java-xxe
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        return factory.newDocumentBuilder();
    }

    DocumentBuilder safeParser() throws Exception {
        // ok: java-xxe
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        return factory.newDocumentBuilder();
    }

    byte[] digest(byte[] data) throws Exception {
        // ruleid: java-weak-hash
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        // ok: java-weak-hash
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        sha.update(data);
        return md5.digest(data);
    }

    static class TrustEverything implements X509TrustManager {
        public void checkClientTrusted(X509Certificate[] chain, String authType) {}
        // ruleid: java-trust-all-certificates
        public void checkServerTrusted(X509Certificate[] chain, String authType) {}
        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
    }

    static class AnyHost implements HostnameVerifier {
        // ruleid: java-trust-all-certificates
        public boolean verify(String host, SSLSession session) { return true; }
    }
}
