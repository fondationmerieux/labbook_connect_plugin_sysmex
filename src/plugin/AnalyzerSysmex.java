package plugin;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.moandjiezana.toml.Toml;

import ca.uhn.hl7v2.HL7Exception;
import ca.uhn.hl7v2.parser.PipeParser;
import ca.uhn.hl7v2.model.Message;
import ca.uhn.hl7v2.model.v251.datatype.ST;
import ca.uhn.hl7v2.model.v251.group.OML_O33_SPECIMEN;
import ca.uhn.hl7v2.model.v251.message.OML_O33;
import ca.uhn.hl7v2.model.v251.message.QBP_Q11;
import ca.uhn.hl7v2.model.v251.segment.MSH;
import ca.uhn.hl7v2.model.v251.segment.QPD;
import ca.uhn.hl7v2.model.v251.segment.RCP;
import ca.uhn.hl7v2.model.v251.segment.SPM;
import ca.uhn.hl7v2.model.v251.message.ACK;

/**
 * Sysmex analyzer connector for LabBook Connect.
 *
 * This implementation supports ASTM record exchanges and (optionally) ASTM E1381-style framing
 * over TCP sockets (ENQ/ACK/NAK, STX...ETX/ETB, checksum, CR/LF, EOT).
 *
 * Transactions handled by this plugin:
 * - LAB-27: analyzer query (ASTM Q record) -> HL7 QBP^Q11 -> HL7 RSP^K11 -> ASTM response.
 * - LAB-29: analyzer results (ASTM H/P/O/R/L) -> HL7 OUL^R22 -> HL7 ACK -> ASTM L|1|Y/N.
 *
 * LAB-28 (HL7 order -> ASTM order) is implemented as best-effort and must be validated
 * against the analyzer configuration (Sysmex models differ on host->analyzer order support).
 *
 * Notes:
 * - Some Sysmex analyzers prepend record numbers (0..7) before the record type (e.g. "1H|...").
 *   This plugin strips those prefixes when parsing.
 * - "ASTM E1381" framing details are used as a reference implementation for the link layer;
 *   actual analyzer behavior may vary slightly by model/firmware.
 */
public class AnalyzerSysmex implements Analyzer {
	
	private static final Logger logger = LoggerFactory.getLogger(AnalyzerSysmex.class); // Uses Connect's logback.xml
	
	private final String jar_version = "1.0.0";

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
    protected String mappingPath = "";
    protected Toml mappingToml = new Toml();

    // === Runtime State ===
    protected AtomicBoolean listening = new AtomicBoolean(false);
    private ServerSocket serverSocket;
    private Socket socket;
    private InputStream inputStream;
    private OutputStream outputStream;
    
    // ASTM control characters
    private static final byte ENQ = 0x05;
    private static final byte ASTM_ACK = 0x06;
    private static final byte ASTM_NAK = 0x15;
    private static final byte EOT = 0x04;
    private static final byte STX = 0x02;
    private static final byte ETX = 0x03;
    private static final byte CR = 0x0D;
    private static final byte LF = 0x0A;
    private static final byte ETB = 0x17; // End of Transmission Block (multi-frame continuation)
    
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
        newAnalyzer.setMappingPath(this.mappingPath);
        return newAnalyzer;
    }

    @Override
    public String test() {
        return this.getClass().getSimpleName();
    }
    
    @Override
    public String info() {
    	return String.format(
    			"Analyzer Info: [Jar=%s, Version=%s, ID=%s, Lab27=%s, Lab29=%s, TypeCnx=%s, TypeMsg=%s, ArchiveMsg=%s, MappingPath=%s, OperationMode=%s, Mode=%s, IP=%s, Port=%d]",
    			this.jar_version, this.version, this.id_analyzer, this.url_upstream_lab27, this.url_upstream_lab29,
    			this.type_cnx, this.type_msg, this.archive_msg, this.mappingPath, this.operation_mode, this.mode, this.ip_analyzer, this.port_analyzer
    			);
    }

    @Override
    public boolean isListening() {
        return this.listening.get();
    }

    // === Methods for LAB Transactions ===

    /**
     * Handles a LAB-27 transaction (ASTM query from analyzer).
     * Converts ASTM Q| message into HL7 QBP^Q11, sends to LabBook,
     * receives RSP^K11, and converts the response back into ASTM format.
     * 
     * @param msg The raw ASTM message received from Sysmex
     * @return ASTM response to send back to analyzer, or null if error
     */
    @Override
    public String lab27(final String msg) {
        logger.info("Lab27 Sysmex : Received ASTM query message\n" + msg);

        try {
            Connect_util.archiveMessage(this.getId_analyzer(), this.archive_msg, msg, "LAB-27", "Analyzer");

            // Parse ASTM message into lines
            String[] astmLines = logAndSplitAstm(msg);

            // Convert ASTM query to HL7 QBP^Q11
            String qbpMsg = convertASTMQueryToQBP_Q11(astmLines);
            if (qbpMsg == null) {
                logger.error("Lab27 Sysmex : Failed to convert ASTM to HL7 QBP^Q11");
                return null;
            }

            logger.info("Lab27 Sysmex : Converted HL7 QBP^Q11\n" + qbpMsg.replace("\r", "\n"));

            // Send QBP^Q11 to LabBook
            String rspMsg = Connect_util.send_hl7_msg(this, this.url_upstream_lab27, qbpMsg);
            logger.info("Lab27 Sysmex : Received RSP^K11 from LabBook\n" + rspMsg.replace("\r", "\n"));
            
            // Convert RSP^K11 back to ASTM message for Sysmex
            String[] astmResponse = convertRSP_K11toASTM(rspMsg);
            if (astmResponse == null || astmResponse.length == 0) {
                logger.error("Lab27 Sysmex : Failed to convert RSP^K11 to ASTM response");
                return null;
            }

            return String.join("\r", astmResponse);  // Send back ASTM response

        } catch (Exception e) {
            logger.error("Lab27 Sysmex : Unexpected error: " + e.getMessage(), e);
            return null;
        }
    }
    
    /**
     * Handles a LAB-28 transaction (order message from LIS to analyzer).
     * Parses the incoming HL7 OML^O33 message, extracts patient/specimen/order info,
     * converts the message into ASTM format, and sends it to the analyzer over socket.
     * 
     * Returns an HL7 ACK^R22 to LabBook (LIS-side acknowledgment).
     * The analyzer acceptance is inferred from the ASTM-level ACK/NAK exchange.
     *
     * @param str_OML_O33 HL7 message string in ER7 format (OML^O33)
     * @return HL7 ACK^R22 message to be returned to LabBook
     */
    @Override
    public String lab28(final String str_OML_O33) {
        logger.info("Lab28 Sysmex : Received message\n" + str_OML_O33.replace("\r", "\r\n"));

        try {
            Connect_util.archiveMessage(this.getId_analyzer(), this.archive_msg, str_OML_O33.replace("\r", "\r\n"), "LAB-28", "LIS");

            PipeParser parser = new PipeParser();
            OML_O33 omlMessage = (OML_O33) parser.parse(str_OML_O33);

            // Log and check number of SPECIMEN groups
            int specimenCount = omlMessage.getSPECIMENReps();
            logger.info("Lab28 Sysmex : Number of SPECIMEN groups = {}", specimenCount);

            if (specimenCount == 0) {
                logger.error("Lab28 Sysmex : Error - No SPECIMEN group found in the message");
                return "ERROR Lab28 Sysmex : No SPECIMEN group found.";
            }

            // Get first SPECIMEN group
            OML_O33_SPECIMEN specimenGroup = omlMessage.getSPECIMEN();

            // Log and check number of ORDER groups in SPECIMEN
            int orderCount = specimenGroup.getORDERReps();
            logger.info("Lab28 Sysmex : Number of ORDER groups in SPECIMEN = {}", orderCount);

            if (orderCount == 0) {
                logger.error("Lab28 Sysmex : Error - No ORDER group found in SPECIMEN");
                return "ERROR Lab28 Sysmex : No ORDER group found.";
            }

            // Proceed with conversion using the complete HL7 message
            String[] astmLines = convertOML_O33ToASTM(str_OML_O33);
            if (astmLines.length == 1 && astmLines[0].startsWith("ERROR")) {
                logger.error("Lab28 Sysmex : Error during conversion to ASTM : " + astmLines[0]);
                return "ERROR Lab28 Sysmex : Invalid OML_O33 message";
            }

            logger.info("Lab28 Sysmex : Converted ASTM message\n" + String.join("\n", astmLines));

            String result = sendASTMMessage(astmLines);

            String ackCode = "AA"; // Default HL7 ACK = accepted
            if (!"ACK".equals(result)) {
                ackCode = "AE"; // Application Error if analyzer rejected the message
            }

            String hl7Ack = generateAckR22(str_OML_O33, ackCode);
            if (hl7Ack != null) {
                logger.info("Lab28 Sysmex : Returning HL7 ACK^R22 to LabBook");
                return hl7Ack;
            } else {
                logger.error("Lab28 Sysmex : Failed to generate HL7 ACK^R22");
                return "ERROR Lab28 Sysmex : Failed to generate HL7 ACK";
            }

        } catch (HL7Exception e) {
            logger.error("Lab28 Sysmex : HL7Exception while processing OML^O33 - " + e.getMessage());
            return "ERROR Lab28 Sysmex : Failed to process OML^O33 message";
        } catch (Exception e) {
            logger.error("Lab28 Sysmex : Unexpected exception - " + e.getMessage(), e);
            return "ERROR Lab28 Sysmex : Unexpected error occurred";
        }
    }

    /**
     * Handles a LAB-29 transaction (ASTM results from analyzer).
     * Parses ASTM result lines into HL7 OUL^R22, forwards to LabBook,
     * receives HL7 ACK, and returns an ASTM L|1|Y or L|1|N acknowledgement.
     *
     * @param msg ASTM message sent by Sysmex (results)
     * @return Minimal ASTM ACK segment or fallback error response
     */
    @Override
    public String lab29(final String msg) {
        logger.info("Lab29 Sysmex : Received ASTM message\n" + msg);

        try {
            Connect_util.archiveMessage(this.getId_analyzer(), this.archive_msg, msg, "LAB-29", "Analyzer");

            // Split the ASTM message into individual lines
            String[] astmLines = logAndSplitAstm(msg);

            // Extract sample ID and handle Background Check case
            String sampleId = extractSampleIdFromAstmLines(astmLines);
            if (isBackgroundCheckSample(sampleId)) {
                logger.info("Lab29 Sysmex : BACKGROUNDCHECK sample detected for ID '" + sampleId + "', message archived, HL7 conversion and upstream send skipped");
                // ASTM positive termination so that the analyzer does not repeat or raise an error
                return "L|1|Y";
            }

            // Convert ASTM to HL7 OUL^R22
            String hl7Message = convertASTMtoOUL_R22(astmLines);
            if (hl7Message == null || hl7Message.isEmpty()) {
                logger.error("Lab29 Sysmex : Error during conversion to HL7 OUL^R22.");
                return "L|1|N"; // ASTM error response
            }

            logger.info("Lab29 Sysmex : Converted HL7 OUL^R22:\n" + hl7Message.replace("\r", "\n"));

            // Send HL7 message to LabBook and get the HL7 ACK response
            String hl7Ack = Connect_util.send_hl7_msg(this, this.url_upstream_lab29, hl7Message);

            if (hl7Ack == null || !hl7Ack.startsWith("MSH|")) {
                logger.error("Lab29 Sysmex : upstream returned non-HL7 or null; returning ASTM NACK. First 80 chars: {}",
                             hl7Ack != null ? hl7Ack.substring(0, Math.min(80, hl7Ack.length())) : "null");
                return "L|1|N";
            }
            logger.info("Lab29 Sysmex : HL7 ACK from LabBook:\n" + hl7Ack.replace("\r", "\n"));

            // Convert HL7 ACK back to a minimal ASTM acknowledgment
            String astmAck = convertACKtoASTM(hl7Ack);
            logger.info("Lab29 Sysmex : Converted ASTM ACK to return:\n" + astmAck);

            return astmAck;

        } catch (Exception e) {
            logger.error("Lab29 Sysmex : Unexpected error - " + e.getMessage(), e);
            return "L|1|N"; // ASTM fallback error response
        }
    }
    
    // === Conversions HL7 <=> ASTM ===
    
    private String[] stripASTMPrefixNumbers(String[] lines) {
        return Arrays.stream(lines)
            .map(line -> line.replaceFirst("^[0-7](?=[A-Z]\\|)", ""))
            .toArray(String[]::new);
    }
    
    /**
     * Convert HL7 OML^O33 order message (coming from LIS) into ASTM lines
     * that are consumable by Sysmex XP (ASTM E1394-97 profile).
     *
     * Sysmex cares mainly about:
     *  - H| header
     *  - P|1   (patient block; XP ignores patient demographics)
     *  - O|... test order
     *  - L|1|N termination
     *
     * Notes:
     *  - Patient demographics (name, DOB, etc.) are ignored by XP series,
     *    so we do not try to send them.
     *  - O|... must follow XP format:
     *    O|1||^^{15-char SampleID}^A|^^^^WBC\\^^^^RBC\\...|...|||N...||F
     *    See XP ASTM spec 9.4.x.
     *    
     * @param oml HL7 message string (ER7) OML^O33
     * @return ASTM lines to send to the analyzer
     */
    public String[] convertOML_O33ToASTM(String oml) {
        List<String> lines = new ArrayList<>();

        try {
            PipeParser parser = new PipeParser();
            OML_O33 message = (OML_O33) parser.parse(oml);

            // --- Extract specimen ID from first SPECIMEN/SPM block ---
            String specimenId = "";
            try {
                OML_O33_SPECIMEN specimenGroup = message.getSPECIMEN();
                SPM spm = specimenGroup.getSPM();
                specimenId = safe(spm.getSpecimenID().getPlacerAssignedIdentifier().getEntityIdentifier());
            } catch (Exception e) {
                logger.warn("convertOML_O33ToASTM: no SPM / specimen ID found in OML^O33");
            }

            // --- Pad Sample ID to 15 chars right-aligned, as per XP spec (field 9.4.4) ---
            // XP expects a 15-char ID, padded with spaces or zeros depending on instrument settings.
            // We'll space-pad on the left so it's right-aligned.
            // Example in spec: ^^     12345ABCDE^B (spaces before ID).
            String paddedSampleId = String.format("%15s", specimenId == null ? "" : specimenId);

            // --- Build test list field (ASTM 9.4.5 Analysis parameter ID) ---
            // According to XP spec, we send repeated parameters separated by "\".
            // Minimal panel: WBC, RBC, HGB, HCT, PLT (you can extend this list if needed).
            String requestedParams =
                "^^^^WBC" + "\\" +
                "^^^^RBC" + "\\" +
                "^^^^HGB" + "\\" +
                "^^^^HCT" + "\\" +
                "^^^^PLT";

            // --- Action Code (ASTM field 9.4.12) ---
            // "N" = normal sample data, "Q" = QC data.
            String actionCode = "N";

            // --- O record construction following Sysmex XP format ---
            // Breakdown:
            // O|
            // 1               -> sequence number
            // |               -> field 9.4.3 "Specimen ID" (not used)
            // |               -> delimiter to field 9.4.4
            // ^^<15-charID>^A -> Instrument Specimen ID (Sample ID padded) + Attribute 'A' (auto assign)
            // |<params>       -> field 9.4.5 repeated analytes (^^^^WBC\^^^^RBC\...)
            // |||||||N        -> skip unused fields until Action Code "N"
            // ||||||||||||||F -> Report Type "F" at the end (field 9.4.26)
            //
            // Important: we keep the exact number of pipes so fields line up.
            String oRecord =
                "O|1||^^" + paddedSampleId + "^A|" +
                requestedParams +
                "|||||||"+ actionCode +"||||||||||||||F";

            // --- Build ASTM lines ---
            // H| per XP when host -> analyzer is basically:
            // H|\^&|||||||||||E1394-97
            // (Spec describes this exact minimal header for Host→XP direction)
            String hRecord = "H|\\^&|||||||||||E1394-97";

            // P|1 only. XP ignores patient info anyway (see 8.1.x table in spec).
            String pRecord = "P|1";

            // L|1|N termination record (always '1' and 'N')
            String lRecord = "L|1|N";

            lines.add(hRecord);
            lines.add(pRecord);
            lines.add(oRecord);
            lines.add(lRecord);

            // Log created lines for debug
            logger.info("convertOML_O33ToASTM: generated ASTM lines for Sysmex:");
            for (String l : lines) {
                logger.info("   {}", l);
            }

            return lines.toArray(new String[0]);

        } catch (Exception e) {
            logger.error("convertOML_O33ToASTM: ERROR while converting OML^O33 to ASTM", e);
            return new String[] { "ERROR: Failed to convert HL7 to ASTM" };
        }
    }
    
    /**
     * Generates an HL7 ACK^R22 message in response to a received OML^O33 order.
     * The ACK reuses key fields (e.g., message control ID, sender/receiver IDs) from the original message.
     *
     * @param originalOML The original HL7 OML^O33 message string
     * @param ackCode The acknowledgment code to return: "AA" (Accept) or "AE" (Error)
     * @return The generated HL7 ACK^R22 message in ER7 format, or null if generation failed
     */
    public String generateAckR22(String originalOML, String ackCode) {
        try {
            PipeParser parser = new PipeParser();
            OML_O33 originalMsg = (OML_O33) parser.parse(originalOML);

            ACK ack = new ACK();
            ack.initQuickstart("ACK", "R22", "P");

            ack.getMSH().getDateTimeOfMessage().getTime().setValue(new SimpleDateFormat("yyyyMMddHHmmss").format(new Date()));
            ack.getMSH().getMessageControlID().setValue(originalMsg.getMSH().getMessageControlID().getValue());
            ack.getMSH().getSendingApplication().parse("Sysmex");
            ack.getMSH().getSendingFacility().parse("Analyzer");
            ack.getMSH().getReceivingApplication().parse(originalMsg.getMSH().getSendingApplication().encode());
            ack.getMSH().getReceivingFacility().parse(originalMsg.getMSH().getSendingFacility().encode());

            ack.getMSA().getAcknowledgmentCode().setValue(ackCode); // "AA" or "AE"
            ack.getMSA().getMessageControlID().setValue(originalMsg.getMSH().getMessageControlID().getValue());

            return parser.encode(ack);
        } catch (Exception e) {
            logger.error("Failed to generate HL7 ACK^R22: " + e.getMessage(), e);
            return null;
        }
    }
    
    /**
     * Converts an ASTM result message into an HL7 v2.5.1 OUL^R22 message (manual build).
     *
     * Parsing behavior:
     * - Accepts ASTM records separated by CR/LF and optionally prefixed with a single digit (0..7)
     *   before the record type (e.g. "1H|...", "2R|..."). Those prefixes are stripped.
     * - Uses the following record types when present:
     *   - P: patient identifier (optional, often empty on Sysmex)
     *   - O: specimen/order identifier (used to populate SPM/ORC/OBR)
     *   - R: result records (mapped to OBX)
     *   - C: comment records (mapped to NTE)
     *
     * Result mapping (R record -> OBX):
     * - OBX-1: incremental index starting at 1
     * - OBX-2: "NM" (numeric) by default
     * - OBX-3: mapped LIS result code if available, otherwise the raw ASTM analyte identifier (R-2)
     * - OBX-4: R-1 (sequence)
     * - OBX-5: R-3 (value), with "no value" placeholders converted to empty
     * - OBX-6: R-4 (unit), overridden by mapping when lis_unit is provided
     * - OBX-8: R-6 (abnormal flag)
     * - OBX-11: "F" (final)
     * - OBX-14: R-12 (timestamp) when present
     * - OBX-16: R-10 (operator/technician) when present
     *
     * Mapping support (TOML):
     * - Matches on vendor_result_code against a normalized form of R-2 (trailing "^&lt;digits&gt;" suffixes removed).
     * - When a match is found, lis_result_code and lis_unit are used (if non-empty).
     * - Optional numeric conversion can be applied to the value using convert/factor (multiply/divide/add/subtract/log10).
     *
     * @param lines ASTM message lines (already split)
     * @return HL7 OUL^R22 in ER7 format, or null on error
     */
    public String convertASTMtoOUL_R22(String[] lines) {
        try {
            lines = stripASTMPrefixNumbers(lines);

            StringBuilder hl7 = new StringBuilder();

            // --- Build HL7 MSH manually ---
            String sendingApp = "Sysmex";
            String sendingFacility = "Analyzer";
            String receivingApp = "LabBook";
            String receivingFacility = "LIS";
            String datetime = new SimpleDateFormat("yyyyMMddHHmmss").format(new Date());
            String controlId = "MSG" + System.currentTimeMillis();

            hl7.append("MSH|^~\\&|")
               .append(sendingApp).append("|")
               .append(sendingFacility).append("|")
               .append(receivingApp).append("|")
               .append(receivingFacility).append("|")
               .append(datetime).append("||")
               .append("OUL^R22|").append(controlId).append("|P|2.5.1\r");

            String patientId = null;
            String specimenId = null;
            int obxIndex = 1;

            for (String line : lines) {
                String[] fields = line.split("\\|", -1);
                if (fields.length == 0) continue;

                switch (fields[0]) {
                    case "P":
                    	// ASTM P record: P|<seq>|<patientId>|...
                        // Some Sysmex configurations send only "P|1" with no identifiers.
                        // When present, we map patientId (P-2) to PID-3.
                        patientId = (fields.length > 2) ? fields[2] : null;
                        hl7.append("PID|||")
                           .append(patientId != null ? patientId : "")
                           .append("||")
                           .append("\r");
                        break;

                    case "O":
                    	/*
                         * ASTM O record: used to derive a specimen/order identifier for HL7.
                         *
                         * Extraction strategy:
                         * - Prefer O field[3] when it starts with "^^" (e.g. "^^<SampleId>^..."), take the first component after the "^^".
                         * - Fallback to O field[2] if field[3] does not provide an identifier.
                         *
                         * HL7 segments produced:
                         * - SPM-2 = specimenId
                         * - ORC-2 = specimenId
                         * - OBR-2 = specimenId
                         * - OBR-4 = raw requested parameter list from O field[4] when present
                         */

                        // specimenId is usually fields[2] OR embedded in fields[3] ("^^<SampleID>^A")
                        specimenId = null;

                        // Try classic ASTM 9.4.4 style in fields[3] = "^^<SampleID>^A"
                        if (fields.length > 3 && fields[3].startsWith("^^")) {
                            // remove leading "^^"
                            String after2hat = fields[3].substring(2);
                            // split "<SampleID>^A"
                            String[] sidParts = after2hat.split("\\^", -1);
                            if (sidParts.length > 0) {
                                specimenId = sidParts[0]; // first piece should be Sample ID
                            }
                        }
                        
                        if (specimenId != null) specimenId = specimenId.trim();

                        // fallback: fields[2]
                        if ((specimenId == null || specimenId.isEmpty()) && fields.length > 2) {
                            specimenId = fields[2];
                            if (specimenId != null) specimenId = specimenId.trim();
                        }

                        // Build SPM segment (SPM-2 = specimen ID)
                        hl7.append("SPM|1|")
                           .append(specimenId != null ? specimenId : "")
                           .append("\r");

                        // Build ORC segment - "RE" (result)
                        hl7.append("ORC|RE|")
                           .append(specimenId != null ? specimenId : "")
                           .append("\r");

                        // Build OBR segment
                        // OBR-2 (placer order number) = specimenId
                        hl7.append("OBR|1|")
                           .append(specimenId != null ? specimenId : "")
                           .append("||");

                        // Put requested parameter list (fields[4]) into OBR-4 if present
                        if (fields.length > 4) {
                            hl7.append(fields[4]);
                        }
                        hl7.append("\r");
                        break;

                    case "R":
                    	/*
                         * ASTM R record -> HL7 OBX.
                         *
                         * The parser consumes only these fields (0-based indexing on `fields[]` after split by '|'):
                         * - fields[1]  : sequence (mapped to OBX-4)
                         * - fields[2]  : analyte identifier (used for mapping and as fallback OBX-3)
                         * - fields[3]  : value (mapped to OBX-5; "no value" tokens become empty)
                         * - fields[4]  : unit (mapped to OBX-6; can be overridden by mapping lis_unit)
                         * - fields[6]  : abnormal flag (mapped to OBX-8)
                         * - fields[10] : operator/technician (mapped to OBX-16 when present)
                         * - fields[12] : timestamp (mapped to OBX-14 when present)
                         *
                         * Mapping rules:
                         * - vendor_result_code is matched against a normalized form of fields[2]
                         *   (trailing "^<digits>" suffixes removed).
                         * - If a match is found, lis_result_code replaces OBX-3 and lis_unit can replace OBX-6.
                         * - Optional numeric conversion is applied on OBX-5 according to convert/factor.
                         */

                        String seq        = (fields.length > 1)  ? fields[1]  : "";
                        String analyte    = (fields.length > 2)  ? fields[2]  : "";
                        String value      = (fields.length > 3)  ? fields[3]  : "";
                        String unit       = (fields.length > 4)  ? fields[4]  : "";
                        String flag       = (fields.length > 6)  ? fields[6]  : "";
                        String operatorId = (fields.length > 10) ? fields[10] : "";
                        String tsEnd      = (fields.length > 12) ? fields[12] : "";
                        
                        // If analyzer sends a "no value" like "----" token, produce an empty OBX-5
                        boolean hasNoValue = isNoValueToken(value);
                        if (hasNoValue) {
                            value = "";
                        }

                        // Mapping: vendor_result_code = raw analyte field (ASTM R|2)
                        String vendorResultCode = normalizeVendorResultCode(analyte);

                        String lisResultCode = "";
                        String lisUnit = "";
                        String convert = "none";
                        double factor = 0.0;
                        
                        // Mapping lookup (TOML):
                        // - Uses global mappings when "test" is missing or empty.
                        // - Matches on vendor_result_code after normalization:
                        //   trailing "^<digits>" suffixes are removed from both the incoming R-2 code and the TOML vendor_result_code.
                        //   This keeps mappings stable across dilution/mode suffix variations
                        List<Toml> maps = mappingToml.getTables("ivd_mapping");
                        if (maps != null && !vendorResultCode.isEmpty()) {
                            for (Toml m : maps) {
                                String vrc = m.getString("vendor_result_code");
                                if (vrc == null) continue;

                                // Allow "test" to be absent/empty in Sysmex mappings (global mapping)
                                String t = m.getString("test");
                                boolean testOk = (t == null || t.trim().isEmpty());

                                String vrcNorm = normalizeVendorResultCode(vrc);
                                
                                if (testOk && vrcNorm.equalsIgnoreCase(vendorResultCode)) {
                                    String lrc = m.getString("lis_result_code");
                                    lisResultCode = (lrc == null) ? "" : lrc.trim();

                                    String lu = m.getString("lis_unit");
                                    lisUnit = (lu == null) ? "" : lu.trim();

                                    String cv = m.getString("convert");
                                    convert = (cv == null) ? "none" : cv.trim();

                                    // factor can be stored as TOML number or string; on parsing errors we fall back to 0.0.
                                    factor = 0.0;
                                    try {
                                        Object factorObj = m.toMap().get("factor");
                                        if (factorObj instanceof Number) {
                                            factor = ((Number) factorObj).doubleValue();
                                        } else if (factorObj instanceof String) {
                                            String s = ((String) factorObj).trim();
                                            if (!s.isEmpty()) {
                                                factor = Double.parseDouble(s.replace(",", "."));
                                            }
                                        }
                                    } catch (Exception ignore) {
                                        factor = 0.0;
                                    }

                                    break;
                                }
                            }
                        }

                        // If lis_unit is defined in the mapping, it overrides the analyzer-provided unit unconditionally.
                        if (!lisUnit.isEmpty()) {
                            unit = lisUnit;
                        }

                        // Apply conversion if configured and value is numeric
                        if (value != null) {
                            String vtrim = value.trim();
                            if (!vtrim.isEmpty() && !"none".equalsIgnoreCase(convert)) {
                                try {
                                    double num = Double.parseDouble(vtrim.replace(",", "."));

                                    if ("multiply".equalsIgnoreCase(convert)) {
                                        num = num * factor;
                                        value = String.valueOf(num);
                                    } else if ("divide".equalsIgnoreCase(convert)) {
                                        if (factor != 0.0) {
                                            num = num / factor;
                                            value = String.valueOf(num);
                                        }
                                    } else if ("add".equalsIgnoreCase(convert)) {
                                        num = num + factor;
                                        value = String.valueOf(num);
                                    } else if ("subtract".equalsIgnoreCase(convert)) {
                                        num = num - factor;
                                        value = String.valueOf(num);
                                    } else if ("log10".equalsIgnoreCase(convert)) {
                                        if (num > 0.0) {
                                            num = Math.log10(num);
                                            value = String.valueOf(num);
                                        }
                                    }
                                } catch (NumberFormatException nfe) {
                                    // Keep raw value if not numeric
                                }
                            }
                        }

                        // Build OBX
                        hl7.append("OBX|")
                           .append(obxIndex).append("|NM|");  // OBX-1, OBX-2

                        // OBX-3: mapped code if present, else raw analyte
                        if (!lisResultCode.isEmpty()) {
                            hl7.append(lisResultCode);
                        } else {
                            hl7.append(analyte);
                        }

                        hl7.append("|")
                           .append(seq).append("|")           // OBX-4
                           .append(value).append("|")         // OBX-5
                           .append(unit).append("|")          // OBX-6
                           .append("||")                      // OBX-7
                           .append(flag).append("|||")        // OBX-8
                           .append("F|")                      // OBX-11
                           .append("||")                      // OBX-12/13
                           .append(tsEnd).append("|")         // OBX-14
                           .append("||")                      // OBX-15
                           .append(operatorId)                // OBX-16
                           .append("\r");

                        obxIndex++;
                        break;

                    case "C":
                    	// ASTM C record (comment) -> HL7 NTE.
                        // We emit one NTE per C line. NTE-1 is kept constant ("1") because LabBook does not require sequencing here.
                        String noteTxt = String.join(" ", Arrays.copyOfRange(fields, 1, fields.length));
                        hl7.append("NTE|1|L|")
                           .append(noteTxt)
                           .append("\r");
                        break;

                    default:
                        // ignore others
                        break;
                }
            }

            return hl7.toString();

        } catch (Exception e) {
            logger.error("Sysmex: Failed to convert ASTM to HL7 OUL_R22", e);
            return null;
        }
    }
    
    /**
     * Converts an HL7 ACK message (typically from LabBook) into a minimal ASTM acknowledgment.
     * 
     * If the ACK contains MSA-1 = "AA" (Application Accept), returns "L|1|Y" (success).
     * For any other acknowledgment code, returns "L|1|N" (failure).
     *
     * @param hl7Ack HL7 ACK message as an ER7-formatted string
     * @return ASTM acknowledgment line (e.g., "L|1|Y" or "L|1|N")
     */
    public String convertACKtoASTM(String hl7Ack) {
        try {
        	if (hl7Ack == null || !hl7Ack.startsWith("MSH|")) {
                logger.error("convertACKtoASTM: Non-HL7 response (no MSH).");
                return "L|1|N";
            }
        	
            PipeParser parser = new PipeParser();
            Message ackMsg = parser.parse(hl7Ack);

            if (!(ackMsg instanceof ACK)) {
                logger.error("convertACKtoASTM: Not an ACK message");
                return "L|1|N";
            }

            ACK ack = (ACK) ackMsg;
            String code = ack.getMSA().getAcknowledgmentCode().getValue();

            // ASTM equivalent: "L|1|Y" if ACK=AA, otherwise "L|1|N"
            return "AA".equals(code) ? "L|1|Y" : "L|1|N";

        } catch (Exception e) {
            logger.error("convertACKtoASTM: Error converting HL7 to ASTM ACK - " + e.getMessage(), e);
            return "L|1|N";
        }
    }
    
    /**
     * Converts ASTM-formatted Sysmex query (e.g., Q line) into an HL7 QBP^Q11 message.
     * @param lines An array of ASTM lines (e.g., starting with Q|...)
     * @return HL7 QBP^Q11 message in ER7 format or null if conversion fails.
     */
    public String convertASTMQueryToQBP_Q11(String[] lines) {
        try {
        	lines = stripASTMPrefixNumbers(lines);
        	
            // Find the line starting with Q| (query block)
            String queryLine = Arrays.stream(lines)
                    .filter(line -> line.startsWith("Q|"))
                    .findFirst()
                    .orElse(null);

            if (queryLine == null) {
                logger.error("convertASTMQueryToQBP_Q11: No Q line found in ASTM input.");
                return null;
            }

            // Split ASTM Q line into fields
            String[] fields = queryLine.split("\\|", -1);

            // Prepare HL7 QBP_Q11 message (HL7 v2.5.1)
            QBP_Q11 qbp = new QBP_Q11();
            qbp.initQuickstart("QBP", "Q11", "P");

            // Fill MSH (standard HL7 header)
            MSH msh = qbp.getMSH();
            msh.getSendingApplication().getNamespaceID().setValue("Sysmex");
            msh.getSendingFacility().getNamespaceID().setValue("Analyzer");
            msh.getReceivingApplication().getNamespaceID().setValue("LabBook");
            msh.getReceivingFacility().getNamespaceID().setValue("LIS");
            msh.getDateTimeOfMessage().getTime().setValue(new SimpleDateFormat("yyyyMMddHHmmss").format(new Date()));
            msh.getMessageControlID().setValue("MSG" + System.currentTimeMillis());
            msh.getVersionID().getVersionID().setValue("2.5.1");

            // Fill QPD segment (Query Parameter Definition)
            QPD qpd = qbp.getQPD();
            qpd.getMessageQueryName().getIdentifier().setValue("LAB-27^IHE");
            qpd.getQueryTag().setValue("SYSMEX");

            // Use ASTM field[2] as specimen ID if available
            if (fields.length > 2) {
                qpd.getField(3, 0).parse(fields[2]);
            }

            // Fill RCP (response control parameters)
            RCP rcp = qbp.getRCP();
            rcp.getQueryPriority().setValue("I");  // I = Immediate

            // Encode to HL7 string
            PipeParser parser = new PipeParser();
            return parser.encode(qbp);

        } catch (Exception e) {
            logger.error("convertASTMQueryToQBP_Q11: Failed to convert ASTM to QBP^Q11: " + e.getMessage(), e);
            return null;
        }
    }
    
    /**
     * Converts HL7 RSP^K11 (worklist / order response from LIS)
     * back into ASTM lines for Sysmex XP.
     *
     * We return minimal Sysmex-friendly ASTM:
     *  H|\\^&amp;|||||||||||E1394-97
     *  P|1
     *  O|1||^^{15-char SampleID}^A|^^^^WBC\\^^^^RBC\\^^^^HGB\\^^^^HCT\\^^^^PLT|||||||N||||||||||||||F
     *  L|1|N
     *
     * Note: we try to extract specimen ID from SPM-2. If multiple patients/specimens
     * are in the RSP, we currently only build one block (first hit).
     * 
     * @param hl7Message HL7 RSP^K11 message string (ER7)
     * @return ASTM lines to send to the analyzer
     */
    public static String[] convertRSP_K11toASTM(String hl7Message) {
        // default values
        String specimenId = "";

        // parse HL7 segments manually
        String[] segments = hl7Message.split("\r");
        for (String segment : segments) {
            if (segment.startsWith("SPM|")) {
                // SPM|1|<specimenId>|...
                String[] f = segment.split("\\|", -1);
                if (f.length > 2) {
                    specimenId = f[2] != null ? f[2] : "";
                    break; // take first specimen only for now
                }
            }
        }

        // pad specimen ID to 15 chars right-aligned like convertOML_O33ToASTM
        String paddedSampleId = String.format("%15s", specimenId);

        // same requestedParams we used in convertOML_O33ToASTM()
        String requestedParams =
            "^^^^WBC" + "\\" +
            "^^^^RBC" + "\\" +
            "^^^^HGB" + "\\" +
            "^^^^HCT" + "\\" +
            "^^^^PLT";

        String actionCode = "N"; // normal sample, not QC

        String hRecord = "H|\\^&|||||||||||E1394-97";
        String pRecord = "P|1";

        String oRecord =
            "O|1||^^" + paddedSampleId + "^A|" +
            requestedParams +
            "|||||||"+ actionCode +"||||||||||||||F";

        String lRecord = "L|1|N";

        return new String[] { hRecord, pRecord, oRecord, lRecord };
    }

    // === Communication Management ===
    
    /**
     * Sends an ASTM message (list of logical records like H|, P|, O|, R|, L|)
     * using ASTM E1381 framing.
     *
     * Steps (host as sender):
     * 1. Send ENQ and wait for ACK from analyzer.
     * 2. For each record line:
     *    - Build a frame: STX + frameNo + line + ETX + checksum + CR + LF
     *    - Send frame
     *    - Wait for ACK/NAK
     *    - If NAK or timeout, retry SAME frame number up to 6 times
     * 3. Send EOT to terminate transmission.
     *
     * Return values:
     *   "ACK"    = all frames accepted
     *   "ERROR"  = timeout / no ACK after 6 retries
     *   (We keep "NAK"/"UNKNOWN" out, we normalize to "ERROR")
     *   
     * @param lines ASTM record lines
     * @return "ACK" if accepted, otherwise "ERROR"
     */
    public String sendASTMMessage(String[] lines) {
        try {
            // --- Phase 1: Establishment (ENQ -> ACK) ---
            logger.info(">>> Sending ENQ");
            outputStream.write(ENQ);
            outputStream.flush();

            socket.setSoTimeout(10000); // 10s max wait for ACK/NAK after ENQ
            int response;
            try {
                response = inputStream.read();
            } catch (SocketTimeoutException e) {
                logger.warn("Timeout waiting for ACK after ENQ (10s)");
                return "ERROR";
            }

            if (response == ASTM_ACK) {
                logger.info("<<< Response after ENQ: ACK");
            } else if (response == ASTM_NAK) {
                logger.warn("<<< Response after ENQ: NAK (remote not ready)");
                // ASTM says: wait >=10s then retry ENQ, etc.
                // We simplify: treat as error for now.
                return "ERROR";
            } else {
                logger.warn("<<< Unexpected byte after ENQ: {}", response);
                return "ERROR";
            }

            // --- Phase 2: Transfer (frame loop) ---
            for (int i = 0; i < lines.length; i++) {
                // Build frame body: <frameNo><recordLine>
                // Frame number cycles 1..7,0 then repeats.
                // Example: STX '1' H|... ETX CS CS CR LF
                String body = ((i + 1) % 8) + lines[i];
                byte[] bodyBytes = body.getBytes(StandardCharsets.US_ASCII);

                // Build frame: STX + body + ETX + checksum + CR + LF
                ByteArrayOutputStream frame = new ByteArrayOutputStream();
                frame.write(STX);
                frame.write(bodyBytes);

                // End-of-text marker: we always send ETX here (single-frame / short messages)
                frame.write(ETX);

                // Compute checksum on [frameNo + payload + ETX]
                int checksum = 0;
                for (byte b : bodyBytes) {
                    checksum += (b & 0xFF);
                }
                checksum += (ETX & 0xFF);
                checksum &= 0xFF;

                String checksumStr = String.format("%02X", checksum);

                frame.write(checksumStr.getBytes(StandardCharsets.US_ASCII));
                frame.write(CR);
                frame.write(LF);

                byte[] frameBytes = frame.toByteArray();

                // Retry logic:
                // ASTM E1381: if receiver returns NAK, we MUST resend the same frame number.
                // Max 6 consecutive attempts. After that we abort.
                boolean sentOk = false;

                for (int attempt = 1; attempt <= 6; attempt++) {
                    logger.info(">>> Sending frame {} attempt {}/6 : {}", (i + 1), attempt, lines[i]);
                    outputStream.write(frameBytes);
                    outputStream.flush();

                    socket.setSoTimeout(10000); // 10s max wait for ACK/NAK

                    int frameResp;
                    try {
                        frameResp = inputStream.read();
                    } catch (SocketTimeoutException e) {
                        logger.warn("Timeout waiting for ACK after frame {} attempt {}", (i + 1), attempt);
                        frameResp = -1; // treat as "no ACK", will retry
                    }

                    if (frameResp == ASTM_ACK) {
                        logger.info("<<< Frame {} accepted (ACK)", (i + 1));
                        sentOk = true;
                        break; // go send next frame
                    }

                    if (frameResp == ASTM_NAK) {
                        logger.warn("<<< Frame {} got NAK, will retry same frame number", (i + 1));
                        // loop continues -> retry SAME frame
                        continue;
                    }

                    // Any unexpected byte or -1 => retry
                    logger.warn("<<< Frame {} unexpected byte {} (will retry same frame)", (i + 1), frameResp);
                    // continue loop without setting sentOk
                }

                // If after 6 tries still not ACKed -> abort transmission
                if (!sentOk) {
                    logger.error("Failed to send frame {} after 6 attempts, aborting transmission", (i + 1));

                    // Send EOT to terminate as per ASTM termination phase
                    logger.info(">>> Sending EOT (abort)");
                    outputStream.write(EOT);
                    outputStream.flush();

                    return "ERROR";
                }
            }

            // --- Phase 3: Termination (EOT) ---
            logger.info(">>> Sending EOT (normal end)");
            outputStream.write(EOT);
            outputStream.flush();

            return "ACK";

        } catch (IOException e) {
            logger.error("ASTM send error: {}", e.getMessage(), e);
            return "ERROR";
        }
    }
    
    /**
     * Gets the mapping configuration path.
     * @return The mapping configuration path.
     */
    @Override
    public String getMappingPath() {
        return this.mappingPath;
    }

    /**
     * Sets the mapping configuration path.
     * @param mappingPath The mapping configuration path.
     */
    @Override
    public void setMappingPath(String mappingPath) {
        this.mappingPath = (mappingPath == null) ? "" : mappingPath.trim();
    }
    
    /**
     * Starts the analyzer I/O loop (client or server mode) in a dedicated daemon thread.
     *
     * - Client mode: connects to the analyzer TCP endpoint, runs the E1381 receive loop, and reconnects
     *   on I/O errors using exponential backoff (5s -> 10s -> ... up to 60s).
     * - Server mode: listens on the configured TCP port and runs the E1381 receive loop per connection.
     *
     * This method loads the mapping TOML once at startup. It does not block the caller thread.
     */
    @Override
    public void listenDevice() {
    	logger.info("DEBUG: this.type_cnx = " + this.type_cnx);
    	logger.info("DEBUG: this.mode = " + this.mode);
    	logger.info("Connecting to analyzer at " + ip_analyzer + ":" + port_analyzer);
    	
        this.mappingToml = Connect_util.loadMappingToml(this.getMappingPath());

    	if (!"socket_E1381".equalsIgnoreCase(this.type_cnx) && !"socket".equalsIgnoreCase(this.type_cnx)) {
    		logger.info("Unsupported connection type: " + type_cnx);
    		this.listening.set(false);
    		return;
    	}

    	Thread mainListener = new Thread(() -> {
    		if ("client".equalsIgnoreCase(this.mode)) {
    			logger.info("Starting ASTM client mode...");

    			int backoffDelayMs = 5000;   // initial 5s
    			final int backoffMaxMs = 60000;  // cap 60s

    			this.listening.set(true);
    			
    		    while (this.listening.get()) {
    				try {
    					// Step 3: open socket
    					connectAsClient();

    					// >>> reset backoff on successful (re)connect
    					backoffDelayMs = 5000;

    					// Step 4: run E1381 FSM (blocks until socket closed or I/O error)
    					this.listening.set(true);
    					listenForIncomingMessages();

    					// Step 5: FSM returned => we'll try to reconnect
    					logger.warn("Client FSM ended; will attempt to reconnect.");

    				} catch (IOException ioEx) {
    					// Step 6: connection/open failure
    					logger.error("Client I/O error: " + ioEx.getMessage(), ioEx);

    				} finally {
    					// Step 7: ensure socket is closed and clear state
    					this.listening.set(false);
    					try { if (socket != null && !socket.isClosed()) socket.close(); } catch (IOException ignore) {}
    					socket = null;
    					inputStream = null;
    					outputStream = null;
    				}

    				// Step 8: wait before next attempt (exponential backoff)
    				try { Thread.sleep(backoffDelayMs); } catch (InterruptedException ie) {
    					Thread.currentThread().interrupt();
    					logger.warn("Reconnect loop interrupted; stopping client mode.");
    					break;
    				}

    				// >>> No Step 9: reconnectSocket();  // not needed, Step 3 will (re)connect
    				backoffDelayMs = Math.min(backoffDelayMs * 2, backoffMaxMs);
    			}
    		} else {
    			// Step 1: Start ASTM server (blocking accept loop; per-connection threads run the FSM)
    			logger.info("Starting ASTM server mode...");
    			startASTMServer(); // never returns
    		}
    	});
    	mainListener.setName("AnalyzerSysmex-MainListener");
    	mainListener.setDaemon(true); // "daemon"
    	mainListener.start();
    }

    /**
     * Opens the TCP socket and initializes input/output streams (client mode).
     * If the socket is already open, this method returns without reinitializing streams.
     *
     * @throws IOException if the TCP connection fails
     */
    public void connectAsClient() throws IOException {
        if (socket != null && !socket.isClosed()) return;
        socket = new Socket(ip_analyzer, port_analyzer);
        inputStream = socket.getInputStream();
        outputStream = socket.getOutputStream();
    }
    
    /**
     * Server mode main loop.
     * Creates a ServerSocket on the configured port and processes one client connection at a time.
     * For each accepted connection, this method runs the ASTM E1381 receive loop until the client disconnects.
     */
    private void startASTMServer() {
    	this.listening.set(true);
        while (this.listening.get()) {
            try {
            	this.serverSocket = new ServerSocket(this.port_analyzer);
                logger.info("ASTM Server started on port {}", this.port_analyzer);
                this.listening.set(true);

                while (true) {
                	if (!this.listening.get()) break;
                    try (Socket clientSocket = this.serverSocket.accept()) {
                        logger.info("Accepted connection from {}", clientSocket.getInetAddress());
                        this.socket = clientSocket;
                        this.inputStream = clientSocket.getInputStream();
                        this.outputStream = clientSocket.getOutputStream();
                        listenForIncomingMessages();
                    } catch (IOException ioEx) {
                        logger.error("ERROR: Client handling failed: {}", ioEx.getMessage(), ioEx);
                    } finally {
                        this.socket = null; 
                        this.inputStream = null; 
                        this.outputStream = null;
                        logger.info("Client connection closed.");
                    }
                }
            } catch (IOException startEx) {
                this.listening.set(false);
                try { if (this.socket != null) this.socket.close(); } catch (IOException ignore) {}
                this.socket = null;
                logger.error("ERROR: Failed to start ASTM server on port {}: {}", this.port_analyzer, startEx.getMessage());
                break;
            } finally {
                try {
                    if (this.serverSocket != null && !this.serverSocket.isClosed()) {
                        this.serverSocket.close();
                    }
                } catch (IOException e) {
                    logger.warn("Error while closing serverSocket in finally: " + e.getMessage(), e);
                } finally {
                    this.serverSocket = null;
                }
            }
        }
    }
    
    /**
     * Returns a printable representation of a control or ASCII byte.
     * Used for logging/debugging low-level byte traffic on the socket.
     *
     * @param b Byte value to convert
     * @return String description (e.g., "ACK", "CR", "LF", or character literal)
     */
    private String printable(int b) {
        if (b >= 32 && b <= 126) return "'" + (char) b + "'";
        switch (b) {
            case 0x02: return "STX";
            case 0x03: return "ETX";
            case 0x04: return "EOT";
            case 0x05: return "ENQ";
            case 0x06: return "ACK";
            case 0x15: return "NAK";
            case 0x0D: return "CR";
            case 0x0A: return "LF";
            case 0x17: return "ETB";
            default: return ".";
        }
    }

    /**
     * Listens for incoming ASTM messages using E1381-style framing on the current socket connection.
     *
     * STEP 1: Wait for ENQ from analyzer, reply with ACK.
     *
     * STEP 2: Receive one or more frames:
     *   - STX, frame number, payload
     *   - ETX or ETB
     *   - checksum (2 ASCII hex chars), CR, LF
     *
     * STEP 3: Validate checksum on [frameNo + payload + ETX/ETB].
     *   - Reply ACK if checksum is valid.
     *   - Reply NAK and wait for retransmission if invalid.
     *
     * STEP 4: Accumulate payload bytes until EOT is received.
     *
     * STEP 5: On EOT, dispatch the assembled ASTM message to LAB-27 or LAB-29.
     *
     * STEP 6: If a response is produced, send it by starting a new ASTM send sequence
     *         (ENQ -> frames -> EOT) using sendASTMMessage().
     *
     * This method processes a single TCP connection and returns when the peer disconnects
     * or when an I/O error occurs.
     */
    private void listenForIncomingMessages() {
        // One connection loop: break to return to startASTMServer()
        while (this.socket != null && !this.socket.isClosed()) {

            if (!this.listening.get()) {
                logger.info("Listening flag is false, exiting listener loop for current connection.");
                break;
            }

            try {
                // STEP 1: Wait for ENQ (15s)
                socket.setSoTimeout(15000);

                int firstByte;
                try {
                    firstByte = inputStream.read();
                } catch (SocketTimeoutException ste) {
                    logger.warn("No data received within 15000 ms while waiting for ENQ — continuing to wait on same connection.");
                    continue;
                }

                if (firstByte == -1) {
                    logger.info("Stream closed by peer during ENQ wait. Ending current connection listener.");
                    break; // end this connection, server loop will accept a new one
                }

                logger.info("<<< DEBUG BYTE 0x{} ({})", String.format("%02X", firstByte), printable(firstByte));
                if (firstByte != ENQ) {
                    logger.warn("Expected ENQ but received: {}", printable(firstByte));
                    // Ignore noise and keep waiting for a proper ENQ on the same connection
                    continue;
                }

                // STEP 2: ACK the ENQ to start the transfer
                outputStream.write(ASTM_ACK);
                outputStream.flush();
                logger.info(">>> Sent ACK [0x06] in response to ENQ");

                // STEP 3: Receive frames until EOT
                ByteArrayOutputStream assembledMessage = new ByteArrayOutputStream();

                framesLoop:
                while (true) {
                    int b = inputStream.read();
                    if (b == -1) {
                        logger.info("Stream closed by peer while waiting for STX/EOT. Ending current connection listener.");
                        break framesLoop;
                    }
                    logger.info("<<< DEBUG BYTE 0x{} ({})", String.format("%02X", b), printable(b));

                    // End of transmission?
                    if (b == EOT) {
                        logger.info("<<< Received EOT — message transmission complete");
                        break framesLoop;
                    }

                    // Expect STX to begin a frame
                    if (b != STX) {
                        logger.warn("Expected STX or EOT, got: {}", printable(b));
                        // ignore noise, continue reading on same connection
                        continue;
                    }

                    // Read frame number
                    int frameNo = inputStream.read();
                    if (frameNo < 0) {
                        throw new IOException("Frame aborted: missing frame number after STX");
                    }

                    // Read payload up to ETX or ETB
                    ByteArrayOutputStream frameContent = new ByteArrayOutputStream();
                    int c;
                    while (true) {
                        c = inputStream.read();
                        if (c < 0) {
                            throw new IOException("Frame aborted: stream closed before ETX/ETB");
                        }
                        if (c == ETX || c == ETB) {
                            break;
                        }
                        frameContent.write(c);
                    }
                    byte terminator = (byte) c; // ETX (final) or ETB (more frames)

                    // Read checksum (2 ASCII hex) + CR + LF
                    int c1 = inputStream.read();
                    int c2 = inputStream.read();
                    int cr = inputStream.read();
                    int lf = inputStream.read();
                    if (c1 < 0 || c2 < 0 || cr < 0 || lf < 0) {
                        throw new IOException("Incomplete trailer after ETX/ETB (checksum/CR/LF missing)");
                    }
                    if (cr != CR || lf != LF) {
                        throw new IOException(String.format("Invalid trailer bytes: CR=0x%02X LF=0x%02X", cr, lf));
                    }
                    String receivedChecksum = "" + (char) c1 + (char) c2;

                    // Compute checksum over [frameNo + payload + terminator]
                    int sum = (frameNo & 0xFF);
                    byte[] payloadBytes = frameContent.toByteArray();
                    for (byte pb : payloadBytes) {
                        sum += (pb & 0xFF);
                    }
                    sum += (terminator & 0xFF);
                    sum &= 0xFF;
                    String expectedChecksum = String.format("%02X", sum);

                    // ACK/NAK based on checksum
                    if (!receivedChecksum.equalsIgnoreCase(expectedChecksum)) {
                        logger.warn("Checksum mismatch: expected {} but got {}", expectedChecksum, receivedChecksum);
                        outputStream.write(ASTM_NAK);
                        outputStream.flush();
                        // Wait for retransmission of the same frame; do not append
                        continue;
                    } else {
                        outputStream.write(ASTM_ACK);
                        outputStream.flush();
                    }

                    // Append frame payload; payload already contains CR between ASTM records
                    assembledMessage.write(payloadBytes);

                    // If terminator == ETB, we expect more frames before EOT
                }

                // Build full ASTM message string
                byte[] assembled = assembledMessage.toByteArray();
                String astmMessage = new String(assembled, StandardCharsets.US_ASCII)
                        .replace("\r\n", "\r")
                        .trim();

                if (astmMessage.isEmpty()) {
                    logger.warn("Empty ASTM message received — ignored.");
                    // Go back to waiting for a new ENQ on same connection
                    continue;
                }
                logger.info("DEBUG: Complete ASTM message:\n{}", astmMessage.replace("\r", "\n"));

                // Dispatch LAB-27 / LAB-29
                String responseMessage = processAnalyzerMsg(astmMessage);
                if (responseMessage != null && !responseMessage.isEmpty()) {
                    logger.info(">>> Sending ASTM response (turnaround):\n{}", responseMessage.replace("\r", "\n"));
                    String[] responseLines = responseMessage
                            .replaceAll("[\\u000d\\u000a]+", "\n")
                            .split("\n");
                    sendASTMMessage(responseLines); // ENQ → ACK → frames → EOT
                } else {
                    logger.warn("No response generated for received ASTM message.");
                }

                // After one full exchange, we just loop back and wait again for ENQ on same socket.
                // If the peer closes, read() will return -1 and we break out above.

            } catch (SocketTimeoutException timeoutEx) {
                logger.warn("No data received within 15000 ms — continuing to wait on current connection...");
                // continue; keep connection open and wait again
            } catch (IOException ioEx) {
                logger.error("Exception in listenForIncomingMessages (ASTM) on current connection: {}", ioEx.getMessage(), ioEx);
                // Stop handling this client, let startASTMServer() accept a new one
                break;
            }
        }

        // Clean client-side resources only; serverSocket is managed by startASTMServer()/stopListening()
        try {
            if (this.socket != null && !this.socket.isClosed()) {
                this.socket.close();
            }
        } catch (IOException ignore) {
            // ignore
        } finally {
            this.socket = null;
            this.inputStream = null;
            this.outputStream = null;
        }
    }

    /**
     * Dispatches the received ASTM message to the appropriate LAB transaction handler.
     * Identifies the type of message by detecting H| (result) or Q| (query) segments.
     *
     * @param receivedMessage Raw ASTM message (decoded, multi-line string)
     * @return Response message (ASTM or HL7), or null if unrecognized or invalid
     */
    private String processAnalyzerMsg(String receivedMessage) {
        try {
            // Normalize to lines
            String[] lines = receivedMessage.replaceAll("[\\u000d\\u000a]+", "\n").split("\n");

            boolean hasH = Arrays.stream(lines).anyMatch(l -> l.matches("^\\d*H\\|.*"));
            boolean hasQ = Arrays.stream(lines).anyMatch(l -> l.matches("^\\d*Q\\|.*"));

            if (hasQ) {
                logger.info("Detected ASTM query message with Q| segment, routing to lab27...");
                return lab27(receivedMessage);
            } else if (hasH) {
                logger.info("Detected ASTM result message with H| segment, routing to lab29...");
                return lab29(receivedMessage);
            } else {
                logger.warn("Received message without recognizable H| or Q| segment, ignored.");
                return null;
            }

        } catch (Exception e) {
            logger.error("ERROR: Exception in processAnalyzerMsg: " + e.getMessage(), e);
            return null;
        }
    }
    
    /**
     * Reads an ASTM message from the input stream using ASTM E1381 framing.
     * Waits for STX...ETX frames, extracts the message body, and strips framing bytes.
     * 
     * Note: This method does not validate checksums.
     *
     * @param inputStream Input stream from the socket (e.g., analyzer connection)
     * @return Full ASTM message as a string (CR-delimited segments), or empty string if none
     * @throws IOException If socket read fails or stream is closed
     */
    public static String readASTMMessage(InputStream inputStream) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        int byteRead;
        int lastPayloadByte = -1;

        boolean inFrame = false;

        while ((byteRead = inputStream.read()) != -1) {
            if (byteRead == 0x04) { // EOT = End Of Transmission
                break;
            }
            if (byteRead == 0x02) { // STX = Start of Text
                inFrame = true;
                lastPayloadByte = -1;
                continue;
            }
            if (byteRead == 0x03) { // ETX = End of Text
                // Frame done – discard following 2 checksum bytes + CR + LF
                inputStream.read(); // Checksum byte 1
                inputStream.read(); // Checksum byte 2
                inputStream.read(); // CR
                inputStream.read(); // LF
                if (lastPayloadByte != '\r') { // ensure single CR delimiter
                    buffer.write('\r');
                }
                inFrame = false;
                lastPayloadByte = -1; // reset for next frame
                continue;
            }
            if (inFrame) {
                buffer.write(byteRead);
                lastPayloadByte = byteRead;
            }
        }

        String msg = buffer.toString(StandardCharsets.US_ASCII).trim();

        if (!msg.isEmpty()) {
            logger.info("Complete ASTM message received:\n{}", msg.replace("\r", "\n"));
        }

        return msg;
    }
    
    @Override
    public void stopListening() {
        listening.set(false);

        try {
            if (this.socket != null && !this.socket.isClosed()) {
                this.socket.close();
            }
        } catch (IOException e) {
            logger.warn("stopListening: error while closing client socket: " + e.getMessage(), e);
        } finally {
            this.socket = null;
            this.inputStream = null;
            this.outputStream = null;
        }

        try {
            if (this.serverSocket != null && !this.serverSocket.isClosed()) {
                this.serverSocket.close();
            }
        } catch (IOException e) {
            logger.warn("stopListening: error while closing server socket: " + e.getMessage(), e);
        } finally {
        	this.serverSocket = null;
        }
    }
    
    // === utility function ===
    
    /**
     * Extracts the specimen/sample ID from the first O|1| record of an ASTM message.
     * Handles optional numeric record prefixes like "1O|...".
     *
     * @param lines ASTM lines (already split and normalized)
     * @return Sample ID (e.g. "20359", "BACKGROUNDCHECK"), or null if not found
     */
    private String extractSampleIdFromAstmLines(String[] lines) {
        for (String rawLine : lines) {
            // Remove optional leading record number (e.g. "1O|" -> "O|")
            String line = rawLine.replaceFirst("^[0-7](?=[A-Z]\\|)", "");
            if (line.startsWith("O|1|")) {
                String[] fields = line.split("\\|", -1);
                if (fields.length > 3) {
                    // fields[3] is usually "^^<SampleID>^A" for Sysmex
                    String orderField = fields[3];
                    String[] comps = orderField.split("\\^", -1);
                    if (comps.length > 2) {
                        return comps[2].trim();
                    }
                }
            }
        }
        return null;
    }

    /**
     * Returns true if the given sample ID corresponds to a Sysmex Background Check.
     *
     * @param sampleId Sample ID extracted from O-record
     * @return true if this is a Background Check sample
     */
    private boolean isBackgroundCheckSample(String sampleId) {
        if (sampleId == null) {
            return false;
        }
        return "BACKGROUNDCHECK".equalsIgnoreCase(sampleId.trim());
    }

    /**
     * Safely extracts value from a primitive ST field (e.g., OBR-4 test name).
     */
    private String safe(ST st) {
        try {
            return st != null ? st.getValue() : "";
        } catch (Exception e) {
            return "";
        }
    }
    
    /**
     * Splits a raw ASTM message into lines using CR/LF normalization,
     * and logs each individual line for debugging purposes.
     *
     * @param msg Raw ASTM message as a single string (may include CR/LF or LF)
     * @return Array of message lines (e.g., H|..., P|..., O|..., etc.)
     */
    private String[] logAndSplitAstm(String msg) {
        String[] lines = msg.replaceAll("[\\u000d\\u000a]+", "\n").split("\n");
        for (String l : lines) {
            logger.info("ASTM line: " + l);
        }
        return lines;
    }
    
    /**
     * Normalizes a Sysmex ASTM analyte identifier for mapping.
     *
     * Sysmex may append a dilution/mode suffix as one or more "^<digits>" blocks
     * (e.g. "^^^^WBC^7", "^^^^WBC^26", or even "^^^^WBC^7^1").
     * This method strips all trailing "^<digits>" blocks so mappings remain stable
     * regardless of dilution/operation mode.
     *
     * Examples:
     *  - "^^^^WBC^7"   -> "^^^^WBC"
     *  - "^^^^WBC^26"  -> "^^^^WBC"
     *  - "^^^^WBC^7^1" -> "^^^^WBC"
     *
     * @param code Raw vendor analyte code from ASTM R-2 (may be null/blank)
     * @return Normalized analyte code without trailing numeric suffixes
     */
    private static String normalizeVendorResultCode(String code) {
        String s = (code == null) ? "" : code.trim();
        if (s.isEmpty()) return "";
        // Drop one or more trailing ^<digits> blocks
        return s.replaceFirst("(\\^\\d+)+$", "");
    }
    
    /**
     * Detects analyzer "no value" placeholders that must not be forwarded as a result value.
     *
     * Some Sysmex outputs use dash tokens (e.g. "----") to indicate that the analyte has
     * no measurable value. In that case, the plugin must generate an HL7 OBX segment with
     * an empty OBX-5 (result value) rather than sending the placeholder text.
     *
     * @param v Raw value extracted from ASTM R-3 (may be null/blank)
     * @return true if the value is considered "no value" and must be treated as empty
     */
    private static boolean isNoValueToken(String v) {
        if (v == null) return true;
        String s = v.trim();
        if (s.isEmpty()) return true;

        // Sysmex "no value" markers seen in LIS prints
        if ("----".equals(s)) return true;
        if ("---".equals(s)) return true;
        if ("--".equals(s)) return true;

        return false;
    }
}