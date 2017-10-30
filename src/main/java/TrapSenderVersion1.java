import org.snmp4j.PDU;
import org.snmp4j.Snmp;
import org.snmp4j.TransportMapping;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.mp.MPv3;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.security.*;
import org.snmp4j.smi.*;
import org.snmp4j.transport.DefaultUdpTransportMapping;
import org.snmp4j.*;
import java.io.IOException;

public class TrapSenderVersion1 {
    static Agent agent;
    private static Snmp snmp = null;

    public static final String community = "public";

    // Sending Trap for sysLocation of RFC1213
    public static final String Oid = ".1.3.6.1.2.1.1.8";

    //IP of Local Host
    public static final String ipAddress = "192.168.50.39";

    //Ideally Port 162 should be used to send receive Trap, any other available Port can be used
    public static final int port = 162;

    public static void main(String[] args) {
        TrapSenderVersion1 trapV1 = new TrapSenderVersion1();
        trapV1.sendTrap_Version2();
    }
    /**
     * This methods sends the V1 trap to the Localhost in port 162
     */
    public void sendTrap_Version1() {
        try {
            // Create Transport Mapping
            TransportMapping transport = new DefaultUdpTransportMapping();
            transport.listen();

            // Create Target
            CommunityTarget cTarget = new CommunityTarget();
            cTarget.setCommunity(new OctetString(community));
            cTarget.setVersion(SnmpConstants.version1);
            cTarget.setAddress(new UdpAddress(ipAddress + "/" + port));
            cTarget.setTimeout(5000);
            cTarget.setRetries(2);

            PDUv1 pdu = new PDUv1();
            pdu.setType(PDU.V1TRAP);
            pdu.setEnterprise(new OID(Oid));
            pdu.setGenericTrap(PDUv1.ENTERPRISE_SPECIFIC);
            pdu.setSpecificTrap(1);
            pdu.setAgentAddress(new IpAddress(ipAddress));

            // Send the PDU
            Snmp snmp = new Snmp(transport);
            System.out.println("Sending V1 Trap... Check Wheather NMS is Listening or not? ");
            snmp.send(pdu, cTarget);
            snmp.close();
        } catch (Exception e) {
            e.printStackTrace();
        }

    }
    public void sendTrap_Version2() {
        try {
            // Create Transport Mapping
            TransportMapping transport = new DefaultUdpTransportMapping();
            transport.listen();

            // Create Target
            CommunityTarget cTarget = new CommunityTarget();
            cTarget.setCommunity(new OctetString(community));
            cTarget.setVersion(SnmpConstants.version2c);
            cTarget.setAddress(new UdpAddress(ipAddress + "/" + port));
            cTarget.setTimeout(5000);
            cTarget.setRetries(2);

            PDU trap = new PDU();
            trap.setType(PDU.TRAP);

            OID oid = new OID(".1.3.6.1.2.1.1.1.0");
            trap.add(new VariableBinding(SnmpConstants.snmpTrapOID, oid));
            trap.add(new VariableBinding(SnmpConstants.sysUpTime, new TimeTicks(5000))); // put your uptime here
            trap.add(new VariableBinding(SnmpConstants.sysDescr, new OctetString("System Description")));

            //Add Payload
            Variable var = new OctetString("some string");
            trap.add(new VariableBinding(oid, var));

            // Send the PDU
            Snmp snmp = new Snmp(transport);
            System.out.println("Sending  Trapv2  to "+ipAddress);
            snmp.send(trap, cTarget);
            snmp.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    public void sendTrap_Version3() {
        try {
            Address targetAddress = GenericAddress.parse("udp:" + ipAddress
                    + "/" + port);
            TransportMapping<?> transport = new DefaultUdpTransportMapping();
            Snmp snmp = new Snmp(transport);
            USM usm = new USM(SecurityProtocols.getInstance()
                    .addDefaultProtocols(), new OctetString(
                    MPv3.createLocalEngineID()), 0);
            SecurityProtocols.getInstance()
                    .addPrivacyProtocol(new PrivAES192());
            SecurityModels.getInstance().addSecurityModel(usm);
            transport.listen();

            snmp.getUSM().addUser(
                    new OctetString("MD5DES"),
                    new UsmUser(new OctetString("MD5DES"), AuthMD5.ID,
                            new OctetString("UserName"), PrivAES128.ID,
                            new OctetString("UserName")));

            // Create Target
            UserTarget target = new UserTarget();
            target.setAddress(targetAddress);
            target.setRetries(1);
            target.setTimeout(11500);
            target.setVersion(SnmpConstants.version3);
            target.setSecurityLevel(SecurityLevel.AUTH_PRIV);
            target.setSecurityName(new OctetString("MD5DES"));

            // Create PDU for V3
            ScopedPDU pdu = new ScopedPDU();
            pdu.setType(ScopedPDU.NOTIFICATION);
            pdu.add(new VariableBinding(SnmpConstants.sysUpTime));
            pdu.add(new VariableBinding(SnmpConstants.snmpTrapOID,
                    SnmpConstants.linkDown));
            pdu.add(new VariableBinding(new OID(Oid), new OctetString(
                    "Major")));

            // Send the PDU
            snmp.send(pdu, target);
            System.out.println("Sending Trap to (IP:Port)=> " + ipAddress + ":"
                    + port);
            snmp.addCommandResponder(new CommandResponder() {
                public void processPdu(CommandResponderEvent arg0) {
                    System.out.println(arg0);
                }
            });
            snmp.close();
        } catch (Exception e) {
            System.err.println("Error in Sending Trap to (IP:Port)=> "
                    + ipAddress + ":" + port);
            System.err.println("Exception Message = " + e.getMessage());
        }
    }




}
