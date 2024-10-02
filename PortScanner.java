import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.nio.channels.SocketChannel;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class PortScanner {  

    private final String targetHost;
    private final ExecutorService executorService;
    private final PortScannerConfig config;

    public PortScanner(String targetHost, PortScannerConfig config) { //Constructor
        this.targetHost = targetHost;
        this.executorService = Executors.newFixedThreadPool(config.getThreadPoolSize());
        this.config = config;
    }

    public Map<Integer, Boolean> scanPorts(ScanType scanType) { //Method for running the port scan 
        Map<Integer, Boolean> scanResults = scanType.scanPorts(executorService, targetHost, config);
        executorService.shutdown();
        try {
            executorService.awaitTermination(Long.MAX_VALUE, TimeUnit.NANOSECONDS);
        } catch (InterruptedException e) {
            System.err.println("Port scanning interrupted.");
            Thread.currentThread().interrupt();
        }
        return scanResults;
    }

    public static void main(String[] args) {  //Main method for the user to enter their input for the scan
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(System.in))) {
            System.out.print("Enter target host: ");
            String targetHost = sanitizeInput(reader.readLine().trim());

            PortScannerConfig config = new PortScannerConfig();
            PortScanner scanner = new PortScanner(targetHost, config);

            System.out.println("Select scan type:");
            System.out.println("1. Common Protocols");
            System.out.println("2. Short Scan (ports 1-1024)");
            System.out.println("3. In-depth Scan (ports 1-65535)");

            System.out.print("Enter your choice: ");
            int choice = Integer.parseInt(sanitizeInput(reader.readLine().trim()));

            ScanType scanType;
            switch (choice) {
                case 1:
                    scanType = new CommonProtocolsScan();
                    break;
                case 2:
                    scanType = new ShortScan();
                    break;
                case 3:
                    scanType = new InDepthScan();
                    break;
                default:
                    System.err.println("Invalid choice.");
                    return;
            }

            Map<Integer, Boolean> scanResults = scanner.scanPorts(scanType);
            scanner.printScanResults(scanResults);

        } catch (NumberFormatException e) {
            System.err.println("Invalid input.");
        } catch (IOException e) {
            System.err.println("Error reading input.");
        }
    }

    private static String sanitizeInput(String input) { //Method to sanitise the user's input
        // Whitelist characters that are allowed
        return input.replaceAll("[^A-Za-z0-9.-]", "");
    }

    private void printScanResults(Map<Integer, Boolean> scanResults) { //Method to display the open ports on the target
        System.out.println("Port Scan Results:");
        for (Map.Entry<Integer, Boolean> entry : scanResults.entrySet()) {
            if (entry.getValue()) {
                System.out.println("Port " + entry.getKey() + " is open");
            }
        }
    }

}

class PortScannerConfig {
    private static final int DEFAULT_THREAD_POOL_SIZE = 50;
    private static final int DEFAULT_TIMEOUT = 2000; 

    private final int threadPoolSize;
    private final int timeout;

    public PortScannerConfig() { //Constructor
        this(DEFAULT_THREAD_POOL_SIZE, DEFAULT_TIMEOUT);
    }

    public PortScannerConfig(int threadPoolSize, int timeout) { //Constructor
        this.threadPoolSize = threadPoolSize;
        this.timeout = timeout;
    }

    // Getters
    public int getThreadPoolSize() {
        return threadPoolSize;
    }

    public int getTimeout() {
        return timeout;
    }
}

interface ScanType {
    Map<Integer, Boolean> scanPorts(ExecutorService executorService, String targetHost, PortScannerConfig config);
}

class CommonProtocolsScan implements ScanType {
    private static final Map<Integer, String> COMMON_PORTS = new HashMap<>();

    static {
        COMMON_PORTS.put(21, "FTP");
        COMMON_PORTS.put(22, "SSH");
        COMMON_PORTS.put(23, "TELNET");
        COMMON_PORTS.put(25, "SMTP");
        COMMON_PORTS.put(53, "DNS");
        COMMON_PORTS.put(80, "HTTP");
        COMMON_PORTS.put(443, "HTTPS");
        COMMON_PORTS.put(3306, "MySQL");
    }

    @Override
    public Map<Integer, Boolean> scanPorts(ExecutorService executorService, String targetHost, PortScannerConfig config) { //Method for assigning task to threads
        Map<Integer, Boolean> scanResults = new HashMap<>();
        COMMON_PORTS.keySet().forEach(port -> executorService.submit(new PortScanTask(port, targetHost, config, scanResults)));
        return scanResults;
    }
}

class ShortScan implements ScanType {
    @Override
    public Map<Integer, Boolean> scanPorts(ExecutorService executorService, String targetHost, PortScannerConfig config) { //Method for assigning task to threads
        Map<Integer, Boolean> scanResults = new HashMap<>();
        for (int port = 1; port <= 1024; port++) {
            executorService.submit(new PortScanTask(port, targetHost, config, scanResults));
        }
        return scanResults;
    }
}

class InDepthScan implements ScanType {
    @Override
    public Map<Integer, Boolean> scanPorts(ExecutorService executorService, String targetHost, PortScannerConfig config) { //Method for assigning task to threads
        Map<Integer, Boolean> scanResults = new HashMap<>();
        for (int port = 1; port <= 65535; port++) {
            executorService.submit(new PortScanTask(port, targetHost, config, scanResults));
        }
        // Wait for all tasks to complete
        executorService.shutdown();
        try {
            executorService.awaitTermination(Long.MAX_VALUE, TimeUnit.NANOSECONDS);
        } catch (InterruptedException e) {
            System.err.println("Port scanning interrupted.");
            Thread.currentThread().interrupt();
        }
        // Filter out closed ports
        scanResults.entrySet().removeIf(entry -> !entry.getValue());
        return scanResults;
    }
}

class PortScanTask implements Runnable {
    private final int port;
    private final String targetHost;
    private final PortScannerConfig config;
    private final Map<Integer, Boolean> scanResults;

    public PortScanTask(int port, String targetHost, PortScannerConfig config, Map<Integer, Boolean> scanResults) { //Constructor
        this.port = port;
        this.targetHost = targetHost;
        this.config = config;
        this.scanResults = scanResults;
    }

    @Override
    public void run() { //Method for performing the scan 
        try {
            SocketChannel socketChannel = SocketChannel.open();
            socketChannel.configureBlocking(true);
            socketChannel.socket().connect(new InetSocketAddress(targetHost, port), config.getTimeout());
            scanResults.put(port, true);
            socketChannel.close();
        } catch (IOException e) {
            // Port is closed or connection timed out
            scanResults.put(port, false);
        }
    }
}
