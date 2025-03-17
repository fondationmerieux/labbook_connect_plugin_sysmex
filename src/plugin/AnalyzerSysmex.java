package plugin;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ca.uhn.hl7v2.HL7Exception;
import ca.uhn.hl7v2.parser.PipeParser;
import ca.uhn.hl7v2.model.Message;
import ca.uhn.hl7v2.model.v251.message.OML_O33;

/**
 * Implementation of the Analyzer interface specific for Sysmex analyzers.
 * <p>
 * This class provides the functionalities needed to communicate with Sysmex analyzers 
 * using ASTM protocol, handling LAB-27, LAB-28, and LAB-29 transactions.
 */
public class AnalyzerSysmex implements Analyzer {
	
	private static final Logger logger = LoggerFactory.getLogger(AnalyzerSysmex.class); // Uses Connect's logback.xml

    // === General Configuration ===
    protected String version = "";
    protected String id_analyzer = "";
    protected String url_upstream_lab27 = "";
    protected String url_upstream_lab29 = "";

    // === Connection Configuration ===
    protected String type_cnx = "";
    protected String type_msg = "";
    protected String archive_msg = "";
    protected String operation_mode = "batch";
    protected String mode = "";
    protected String ip_analyzer = "";
    protected int port_analyzer = 0;

    // === Runtime State ===
    protected boolean listening = false;
    private Socket socket;
    private InputStream inputStream;
    private OutputStream outputStream;
    private String expectedResponse = null;
    private final Object responseLock = new Object();
    private boolean waitingForResponse = false;
    
    /**
     * Default constructor.
     * <p>
     * Instantiates a new AnalyzerSysmex with default settings.
     */
    public AnalyzerSysmex() {
    }

    // === Getters and Setters ===
    @Override
    public String getId_analyzer() {
        return id_analyzer;
    }

    @Override
    public void setId_analyzer(String id_analyzer) {
        this.id_analyzer = id_analyzer;
    }

    @Override
    public String getUrl_upstream_lab27() {
        return url_upstream_lab27;
    }

    @Override
    public void setUrl_upstream_lab27(String url) {
        this.url_upstream_lab27 = url;
    }

    @Override
    public String getUrl_upstream_lab29() {
        return url_upstream_lab29;
    }

    @Override
    public void setUrl_upstream_lab29(String url) {
        this.url_upstream_lab29 = url;
    }

    @Override
    public void setVersion(String version) {
        this.version = version;
    }

    @Override
    public void setType_cnx(String type_cnx) {
        this.type_cnx = type_cnx;
    }

    @Override
    public void setType_msg(String type_msg) {
        this.type_msg = type_msg;
    }

    @Override
    public void setArchive_msg(String archive_msg) {
        this.archive_msg = archive_msg;
    }
    
    @Override
    public void setOperationMode(String operation_mode) {
        this.operation_mode = operation_mode;
    }

    @Override
    public void setMode(String mode) {
        this.mode = mode;
    }

    @Override
    public void setIp_analyzer(String ip_analyzer) {
        this.ip_analyzer = ip_analyzer;
    }

    @Override
    public void setPort_analyzer(int port_analyzer) {
        this.port_analyzer = port_analyzer;
    }

    // === Core Functionalities ===

    @Override
    public AnalyzerSysmex copy() {
        AnalyzerSysmex newAnalyzer = new AnalyzerSysmex();
        newAnalyzer.setId_analyzer(this.id_analyzer);
        newAnalyzer.setVersion(this.version);
        newAnalyzer.setUrl_upstream_lab27(this.url_upstream_lab27);
        newAnalyzer.setUrl_upstream_lab29(this.url_upstream_lab29);
        newAnalyzer.setType_cnx(this.type_cnx);
        newAnalyzer.setType_msg(this.type_msg);
        newAnalyzer.setArchive_msg(this.archive_msg);
        newAnalyzer.setMode(this.mode);
        newAnalyzer.setIp_analyzer(this.ip_analyzer);
        newAnalyzer.setPort_analyzer(this.port_analyzer);
        return newAnalyzer;
    }

    @Override
    public String test() {
        return this.getClass().getSimpleName();
    }
    
    @Override
    public String info() {
        return String.format(
            "Analyzer Info: [Version=%s, ID=%s, Lab27=%s, Lab29=%s, TypeCnx=%s, TypeMsg=%s, ArchiveMsg=%s, OperationMode=%s, Mode=%s, IP=%s, Port=%d]",
            this.version, this.id_analyzer, this.url_upstream_lab27, this.url_upstream_lab29,
            this.type_cnx, this.type_msg, this.archive_msg, this.operation_mode, this.mode, this.ip_analyzer, this.port_analyzer
        );
    }

    @Override
    public boolean isListening() {
        return this.listening;
    }

    // === Methods for LAB Transactions ===

    @Override
    public String lab27(final String msg) {
        return processLabTransaction(msg, "LAB-27", this.url_upstream_lab27);
    }

    @Override
    public String lab28(final String str_OML_O33) {
        logger.info("Lab28 Sysmex : Received message\n" + str_OML_O33);

        try {
            Connect_util.archiveMessage(this.getId_analyzer(), this.archive_msg, str_OML_O33, "LAB-28", "LIS");

            PipeParser parser = new PipeParser();
            OML_O33 omlMessage = (OML_O33) parser.parse(str_OML_O33);

            if (omlMessage.getSPECIMENReps() == 0) {
                logger.error("Lab28 Sysmex Error: No SPECIMEN segment found in the OML^O33 message.");
                return "Error: No SPECIMEN segment found.";
            }

            String formattedHL7 = parser.encode(omlMessage);
            logger.info("Lab28 Sysmex Formatted HL7 message:\n" + formattedHL7.replace("\r", "\n"));

            return sendHL7MessageToAnalyzer(formattedHL7);

        } catch (HL7Exception e) {
            logger.error("ERROR Lab28 Sysmex processing OML^O33 message: " + e.getMessage());
            return "ERROR Lab28 Sysmex : Failed to process OML^O33 message";
        } catch (Exception e) {
            logger.error("ERROR Lab28 Sysmex unexpected error: " + e.getMessage());
            return "ERROR Lab28 Sysmex : Unexpected error occurred";
        }
    }


    @Override
    public String lab29(final String msg) {
        return processLabTransaction(msg, "LAB-29", this.url_upstream_lab29);
    }

    private String processLabTransaction(String msg, String labType, String url) {
        logger.info(labType + " Sysmex: Received message\n" + msg);
        try {
            Connect_util.archiveMessage(this.getId_analyzer(), this.archive_msg, msg, labType, "Analyzer");
            String response = Connect_util.send_hl7_msg(this, url, msg.replace("\r", "\n"));
            logger.info("DEBUG: Response from LIS:\n" + response.replace("\r", "\n"));
            return response;
        } catch (Exception e) {
        	logger.error("Unexpected error during LAB transaction processing: " + e.getMessage(), e);
            return "ERROR: LIS transmission failed";
        }
    }

    // === Communication Management ===

    /**
     * Sends an HL7-formatted message to the analyzer via the active socket connection and waits synchronously for the response.
     * <p>
     * The method first encapsulates the provided HL7 message using the standard MLLP framing protocol.
     * It then sends the framed message through the established socket connection.
     * <p>
     * After sending, the method waits synchronously for the response message to be returned by the analyzer.
     * If the response isn't received within a defined timeout period, the method returns an appropriate error message indicating a timeout.
     * <p>
     * This method handles exceptions related to I/O errors (such as network issues) and thread interruptions gracefully.
     *
     * @param hl7Message The HL7 message (plain string) to be sent.
     * @return The HL7 response message from the analyzer, or an error message if a timeout or other issue occurs.
     */
    public String sendHL7MessageToAnalyzer(String hl7Message) {
        if (socket == null || socket.isClosed() || outputStream == null) {
            return "ERROR: No active connection";
        }

        try {
            synchronized (responseLock) {
                expectedResponse = null;
                waitingForResponse = true;
            }

            String framedMessage = Connect_util.encapsulateHL7Message(hl7Message);
            outputStream.write(framedMessage.getBytes(StandardCharsets.UTF_8));
            outputStream.flush();
            logger.info("DEBUG: Sent HL7 message:\n" + hl7Message.replace("\r", "\n"));

            synchronized (responseLock) {
                long startTime = System.currentTimeMillis();
                while (expectedResponse == null && (System.currentTimeMillis() - startTime) < 5000) {
                    responseLock.wait(500);
                }
                waitingForResponse = false;

                if (expectedResponse == null) {
                    return "ERROR: Response timeout";
                }
                return expectedResponse;
            }

        } catch (IOException | InterruptedException e) {
            Thread.currentThread().interrupt();
            logger.error("ERROR sending HL7 message: " + e.getMessage());
            return "ERROR: Sending failed";
        }
    }

    /**
     * Starts the communication listener thread for the analyzer device.
     * <p>
     * Depending on the configured connection type, this method initializes a socket connection in client mode
     * or logs an unsupported configuration message. The connection attempt utilizes exponential backoff
     * for reconnection attempts, starting with a 5-second delay and doubling the wait time after each failed attempt,
     * up to a maximum of 1 minute.
     * <p>
     * Once connected, the method continuously listens for incoming messages from the analyzer, setting
     * the internal `listening` state to true upon successful connection. It resets the backoff timer after every successful
     * connection. In case of connection errors or interruptions, the socket connection will be retried automatically.
     * <p>
     * This method runs continuously in a separate thread to avoid blocking the main application flow.
     */
    @Override
    public void listenDevice() {
        logger.info("DEBUG: this.type_cnx = " + this.type_cnx);
        logger.info("DEBUG: this.mode = " + this.mode);
        logger.info("Connecting to analyzer at " + ip_analyzer + ":" + port_analyzer);

        if ("socket".equalsIgnoreCase(this.type_cnx)) {
            new Thread(() -> {
                int backoffTime = 5000; // Initial delay (5s)
                int maxBackoffTime = 60000; // Max delay (1 min)

                while (true) {
                    try {
                        if ("client".equalsIgnoreCase(this.mode)) {
                            logger.info("DEBUG: Starting HL7 client mode...");
                            connectAsClient();
                        } else {
                            logger.info("DEBUG: Starting HL7 server mode...");
                            startHL7Server();
                        }

                        if (socket == null || socket.isClosed()) {
                            throw new IOException("Connection could not be established.");
                        }

                        this.listening = true;
                        backoffTime = 5000; // Reset backoff after successful connection
                        logger.info("DEBUG: listenDevice() successfully started.");

                        listenForIncomingMessages();

                        while (this.listening) {
                            if (socket == null || socket.isClosed()) {
                                logger.info("DEBUG: Connection lost, attempting reconnection...");
                                reconnectSocket();
                                logger.info("DEBUG: Waiting " + backoffTime + "ms before next reconnection attempt...");
                                Thread.sleep(backoffTime);
                                backoffTime = Math.min(backoffTime * 2, maxBackoffTime);
                            }
                            Thread.sleep(5000);
                        }

                    } catch (IOException | InterruptedException e) {
                        logger.error("ERROR: " + e.getMessage());
                        this.listening = false;
                    }
                }
            }).start();
        } else {
            logger.info("Unsupported connection type: " + type_cnx);
            this.listening = false;
        }
    }

    /**
     * Establishes a connection to the analyzer in CLIENT mode.
     * <p>
     * This method initializes the socket connection using the configured IP address and port of the analyzer.
     * It sets up input and output streams for subsequent message exchanges (e.g., HL7 transactions).
     * <p>
     * If a connection already exists and is open, no action is performed.
     *
     * @throws IOException if the connection attempt fails due to network errors or invalid connection parameters.
     */
    public void connectAsClient() throws IOException {
        if (socket != null && !socket.isClosed()) return;
        socket = new Socket(ip_analyzer, port_analyzer);
        inputStream = socket.getInputStream();
        outputStream = socket.getOutputStream();
    }
    
    /**
     * Starts an HL7 MLLP server that listens for incoming HL7 messages.
     */
    private void startHL7Server() {
        while (true) {
            try (ServerSocket serverSocket = new ServerSocket(port_analyzer)) {
                logger.info("DEBUG: HL7 Server started on port " + port_analyzer);

                while (true) {
                    try {
                        // Wait for incoming client connection
                        Socket clientSocket = serverSocket.accept();
                        logger.info("DEBUG: Accepted connection from " + clientSocket.getInetAddress());

                        // Handle each client connection in a separate thread
                        new Thread(() -> handleClientConnection(clientSocket)).start();

                    } catch (IOException e) {
                        logger.error("ERROR: Failed to accept client connection: " + e.getMessage());
                    }
                }
            } catch (IOException e) {
                logger.error("ERROR: Failed to start HL7 server on port " + port_analyzer + ": " + e.getMessage());
                logger.info("DEBUG: Retrying in 10 seconds...");
                try {
                    Thread.sleep(10000); // Wait 10 seconds before retrying
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    logger.error("ERROR: Server retry interrupted.");
                    break;
                }
            }
        }
    }
    
    /**
     * Handles an HL7 client connection.
     *
     * @param clientSocket The socket connected to the HL7 client.
     */
    private void handleClientConnection(Socket clientSocket) {
        try (InputStream clientInputStream = clientSocket.getInputStream();
             OutputStream clientOutputStream = clientSocket.getOutputStream()) {

            // Read incoming HL7 message
            String receivedMessage = Connect_util.readMLLPMessage(clientInputStream);
            if (!receivedMessage.isEmpty()) {
                logger.info("DEBUG: Received HL7 message:\n" + receivedMessage.replace("\r", "\n"));

                // Forward the message to the analyzer
                String response = processAnalyzerMsg(receivedMessage);

                // If the analyzer provides a response, send it back to the client
                if (response != null && !response.isEmpty()) {
                	logger.info("DEBUG: Preparing to send ACK:\n" + response.replace("\r", "\n"));

                    // Ensure the ACK is properly encapsulated in MLLP
                    String mllpAck = Connect_util.encapsulateHL7Message(response);

                    // Send the encapsulated ACK to the client
                    clientOutputStream.write(mllpAck.getBytes(StandardCharsets.UTF_8));
                    clientOutputStream.flush();  // Ensure all bytes are sent

                    logger.info("DEBUG: ACK sent successfully to the analyzer.");
                } else {
                    logger.warn("WARNING: No ACK generated, nothing sent to the analyzer.");
                }
            }
        } catch (IOException e) {
            logger.error("ERROR: Failed to process HL7 message: " + e.getMessage());
        } finally {
            try {
                clientSocket.close();
            } catch (IOException e) {
                logger.error("ERROR: Failed to close client socket: " + e.getMessage());
            }
        }
    }
    
    /**
     * Attempts to reconnect the socket connection.
     */
    private void reconnectSocket() {
        try {
            if (socket != null && !socket.isClosed()) {
                socket.close();
            }
            connectAsClient();
        } catch (IOException e) {
            logger.error("ERROR: Reconnection failed: " + e.getMessage());
        }
    }

    /**
     * Listens for incoming HL7 messages on an open socket connection.
     * It processes valid HL7 messages while preventing unnecessary logging for empty reads.
     */
    private void listenForIncomingMessages() {
        while (this.listening) {
            try {
                // Check if there is data available before attempting to read
                if (this.inputStream.available() == 0) {
                    Thread.sleep(500);  // Passive wait to avoid busy looping
                    continue;
                }

                // Read the HL7 message encapsulated in MLLP format
                String receivedMessage = Connect_util.readMLLPMessage(this.inputStream);

                // Ensure that a valid message was received before processing
                if (receivedMessage.isEmpty()) {
                    Thread.sleep(500);  // Avoid excessive logging and CPU usage
                    continue;
                }

                synchronized (responseLock) {
                    if (waitingForResponse) {  
                        // Store the expected response and notify waiting threads
                        expectedResponse = receivedMessage;
                        responseLock.notifyAll();
                        waitingForResponse = false;
                        logger.info("DEBUG: Stored expected HL7 response.");
                    } else {
                        logger.info("DEBUG: Received from analyzer an HL7 message:\n" + receivedMessage.replace("\r", "\n"));
                        // Process the message and retrieve the response
                        String responseMessage = processAnalyzerMsg(receivedMessage);

                        // If a response is generated, send it back to the analyzer
                        if (responseMessage != null && !responseMessage.isEmpty()) {
                            try {
                                if (this.outputStream != null) {
                                    // Encapsulate the HL7 message using MLLP format and send it through the socket
                                    this.outputStream.write(Connect_util.encapsulateHL7Message(responseMessage).getBytes(StandardCharsets.UTF_8));
                                    this.outputStream.flush();
                                    logger.info("DEBUG: Sent HL7 response to analyzer:\n" + responseMessage.replace("\r", "\n"));
                                } else {
                                    logger.error("ERROR: Output stream is null, cannot send response.");
                                }
                            } catch (IOException e) {
                                logger.error("ERROR: Failed to send HL7 response to analyzer: " + e.getMessage());
                            }
                        } else {
                            logger.warn("WARNING: processAnalyzerMsg() did not return a response.");
                        }
                    }
                }

            } catch (IOException | InterruptedException e) {
                this.listening = false;
                logger.error("ERROR: Exception in listenForIncomingMessages: " + e.getMessage());
            }
        }
    }

    /**
     * Processes incoming HL7 messages, determines the message type,
     * forwards it to the LIS if necessary, and returns the appropriate acknowledgment (ACK).
     *
     * @param hl7Message The received HL7 message.
     * @return A response HL7 message (ACK) if applicable, otherwise null.
     */
    private String processAnalyzerMsg(String hl7Message) {
        try {
            PipeParser parser = new PipeParser();
            parser.getParserConfiguration().setValidating(false);

            // Parse the HL7 message
            Message message = parser.parse(hl7Message);
            String messageType = message.getName();
            logger.info("DEBUG: messageType = " + messageType);

            String responseMessage = null;
            
            // Determine the message type and forward it accordingly
            if (messageType.contains("OUL_R22")) {
                responseMessage = lab29(hl7Message); // Forward to LIS and return ACK to the analyzer
                logger.info("DEBUG: Response message from LIS on lab29:\n" + responseMessage);
            } else if (messageType.contains("QBP_Q11")) {
                responseMessage = lab27(hl7Message);
                logger.info("DEBUG: Response message from LIS on lab27:\n" + responseMessage);
            } else {
                logger.info("DEBUG: Received an unknown HL7 message type.");
                return null;
            }
            
            // If an ACK is generated, encapsulate it in MLLP before returning
            if (responseMessage != null) {
                responseMessage = Connect_util.encapsulateHL7Message(responseMessage);
                logger.info("DEBUG: Encapsulated ACK response in MLLP format: " + responseMessage.replace("\r", "\n"));
            }

            return responseMessage;

        } catch (HL7Exception e) {
            logger.error("ERROR: Failed to parse HL7 message: " + e.getMessage());
            return null;
        }
    }

}