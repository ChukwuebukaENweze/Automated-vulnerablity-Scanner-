# Automated-vulnerablity-Scanner-
Developed a simple network vulnerability scanner designed to identify common vulnerabilities in remote systems by checking open ports, identifying outdated software based on banner grabbing, and illustrating the concept of missing patch checks.





import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;

public class AutomantedVulnerabilityScanner {

    private static final int TIMEOUT = 2000; // 2 seconds timeout for port check
    private static final int[] COMMON_PORTS = {21, 22, 23, 80, 443}; // Common ports

    // A simple map of version -> vulnerable status for illustrative purposes
    private static final String[] KNOWN_VULNERABLE_SOFTWARE_VERSIONS = {
        "Apache/2.2.8", // Example of a known vulnerable version of Apache
        "OpenSSH_7.2", // Example of a known vulnerable version of OpenSSH
        "vsftpd/2.3.4" // Known vulnerable version of vsftpd
    };

    public static void main(String[] args) {
        String target = "example.com"; // Replace with the actual target

        // Step 1: Check for open ports
        List<Integer> openPorts = checkOpenPorts(target);
        if (!openPorts.isEmpty()) {
            System.out.println("Open Ports: " + openPorts);
        } else {
            System.out.println("No common open ports found.");
        }

        // Step 2: Check for outdated software on open ports
        for (int port : openPorts) {
            checkOutdatedSoftware(target, port);
        }

        // Step 3: Check for missing patches (illustrative)
        checkMissingPatches(target);
    }

    private static List<Integer> checkOpenPorts(String host) {
        List<Integer> openPorts = new ArrayList<>();
        try {
            for (int port : COMMON_PORTS) {
                try (Socket socket = new Socket()) {
                    socket.connect(new InetSocketAddress(InetAddress.getByName(host), port), TIMEOUT);
                    openPorts.add(port); // Add port to list if open
                } catch (IOException e) {
                    // Port is closed or unreachable
                    System.out.println("Port " + port + " is closed or unreachable.");
                }
            }
        } catch (Exception e) {
            System.err.println("Error checking open ports: " + e.getMessage());
        }
        return openPorts;
    }

    private static void checkOutdatedSoftware(String host, int port) {
        try {
            Socket socket = new Socket();
            socket.connect(new InetSocketAddress(host, port), TIMEOUT);
            BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));

            // For HTTP services (port 80 or 443), send a simple HTTP request to grab the banner
            if (port == 80 || port == 443) {
                // Send a basic HTTP GET request
                socket.getOutputStream().write(("GET / HTTP/1.1\r\nHost: " + host + "\r\n\r\n").getBytes());
                socket.getOutputStream().flush();

                // Read the response headers
                String banner = null;
                String line;
                while ((line = reader.readLine()) != null) {
                    if (line.startsWith("Server:")) {
                        banner = line;
                        break;  // Server header contains version info (e.g., Apache/2.2.8)
                    }
                }

                if (banner != null) {
                    System.out.println("Banner from port " + port + ": " + banner);
                    checkForVulnerabilities(banner); // Check if the version is vulnerable
                } else {
                    System.out.println("No server banner found on port " + port);
                }
            }
            socket.close();
        } catch (IOException e) {
            System.out.println("Error retrieving banner from port " + port + ": " + e.getMessage());
        }
    }

    private static void checkForVulnerabilities(String banner) {
        for (String vulnerableVersion : KNOWN_VULNERABLE_SOFTWARE_VERSIONS) {
            if (banner.contains(vulnerableVersion)) {
                System.out.println("WARNING: Vulnerable software found! Version: " + vulnerableVersion);
                break;
            }
        }
    }

    private static void checkMissingPatches(String host) {
        // This is just a placeholder. In a real scan, you'd integrate with a CVE database.
        System.out.println("Checking for missing patches (illustrative only, not implemented).");
        //only implemented cause it requires a real-time vulnerability database
    }
}
