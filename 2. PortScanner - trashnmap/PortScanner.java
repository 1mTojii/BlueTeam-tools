import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.io.IOException;

/**
 * PortScanner - a simple TCP connect-scan tool.
 *
 * this is just a simple PortScanner
 *
 * This file is a SKELETON. The method signatures and structure are here,
 * but the actual logic (marked with TODO) is for you to write.
 *
 * ----------------------------------------------------------------------
 * USAGE (once finished):
 *   javac PortScanner.java
 *   java PortScanner <host> <startPort> <endPort>
 *
 * Example:
 *   java PortScanner scanme.nmap.org 20 100
 * ----------------------------------------------------------------------
 */
public class PortScanner {

    // Default connection timeout in milliseconds. Feel free to make this
    // a command-line argument later once the basics work.
    static final int DEFAULT_TIMEOUT_MS = 500;

    public static void main(String[] args) {
        // TODO 1: Parse command-line arguments.
        args[0] = "host"
        args[1] = "1"
        args[2] = "4040"
        //
        // Hints:
        if (args.length > 3) {

        }

        //   - Check args.length before accessing indices, or you'll get
        //     an ArrayIndexOutOfBoundsException if the user forgets a flag.
        //   - Integer.parseInt(args[1]) converts a String to an int.
        //   - If parsing fails (NumberFormatException), print a usage
        //     message and exit instead of crashing with a stack trace.
        //
        // TODO 2: Once you have host/startPort/endPort, call scanRange(...)
        // with them.

        System.out.println("TODO: implement argument parsing and call scanRange()");
    }

    /**
     * Attempts to open a TCP connection to a single port.
     *
     * @param host      target hostname or IP
     * @param port      port number to test
     * @param timeoutMs how long to wait before giving up (in milliseconds)
     * @return true if the port accepted a connection (i.e. it's open), false otherwise
     */
    static boolean isPortOpen(String host, int port, int timeoutMs) {
        // TODO: Implement the actual connect attempt.
        //
        // Approach:
        //   1. Create a new Socket() (the no-arg constructor -- don't connect yet).
        //   2. Call socket.connect(new InetSocketAddress(host, port), timeoutMs).
        //      - This is a BLOCKING call that throws an exception if it fails.
        //      - SocketTimeoutException -> connection timed out (probably filtered/firewalled)
        //      - IOException (e.g. ConnectException) -> connection actively refused (port closed)
        //   3. If connect() returns without throwing, the port is open -- return true.
        //   4. Make sure the socket gets closed either way (try-with-resources
        //      handles this automatically: `try (Socket socket = new Socket()) { ... }`)
        //
        // Think about: what should happen in each catch block? What should
        // this method return in each case?

        throw new UnsupportedOperationException("isPortOpen() not implemented yet");
    }

    /**
     * Scans a range of ports on the given host and prints results as it goes.
     *
     * @param host      target hostname or IP
     * @param startPort first port to scan (inclusive)
     * @param endPort   last port to scan (inclusive)
     * @param timeoutMs per-port connection timeout in milliseconds
     */
    static void scanRange(String host, int startPort, int endPort, int timeoutMs) {
        // TODO: Loop from startPort to endPort (inclusive).
        //   - For each port, call isPortOpen(host, port, timeoutMs).
        //   - If it returns true, print something like: "Port 22 -- OPEN"
        //   - (Optional, do this later) print progress so the user knows
        //     it's not frozen, e.g. every 100 ports.
        //
        // Think about: what happens if startPort > endPort? Should you
        // validate that before looping?

        System.out.println("TODO: implement the scanning loop");
    }
}
