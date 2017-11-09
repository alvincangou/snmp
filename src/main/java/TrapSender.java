import org.snmp4j.PDU;
import org.snmp4j.Snmp;
import org.snmp4j.TransportMapping;
import org.snmp4j.mp.MPv3;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.security.*;
import org.snmp4j.smi.*;
import org.snmp4j.transport.DefaultUdpTransportMapping;
import org.snmp4j.*;

public class TrapSender {
    static Agent agent;
    private static Snmp snmp = null;

    OID oid1 = new OID(".1.3.6.1.4.1.50966.1.1.1");
    OID oid2 = new OID(".1.3.6.1.4.1.50966.1.1.2");
    OID oid3 = new OID(".1.3.6.1.4.1.50966.1.1.3");
    OID oid4 = new OID(".1.3.6.1.4.1.50966.1.1.4");
    OID oid5 = new OID(".1.3.6.1.4.1.50966.1.1.5");
    OID oid6 = new OID(".1.3.6.1.4.1.50966.1.1.6");

    public static final String community = "public";

    // Sending Trap for sysLocation of RFC1213
    //public static final String Oid = ".1.3.6.1.2.1.1.8";
      public static final String Oid = ".1.3.6.1.4.1.50966.1.1";
    //IP of Local Host
    public static final String ipAddress = "192.168.50.39";

    //Ideally Port 162 should be used to send receive Trap, any other available Port can be used
    public static final int port = 162;

    public static void main(String[] args) {

        Variable id = new OctetString("some string");
        Variable category = new OctetString("some string");
        Variable query = new OctetString("some string");
        Variable label = new OctetString("some string");
        Variable status = new OctetString("some string");
        Variable url = new OctetString("some string");
        TrapSender sender = new TrapSender();
sender.sendTrap_Param(3,id,category,query,label,status,url);

    }

public void sendTrap_Param(int version, Variable id, Variable Category, Variable Query, Variable Label , Variable Status, Variable URL){
if (version == 1 ){
    sendTrap_Version1(id,Category,Query,Label,Status,URL);
}else if (version ==2){
    sendTrap_Version2(id,Category,Query,Label,Status,URL);
}else if (version==3){
    sendTrap_Version3(id,Category,Query,Label,Status,URL);
    }
    else sendTrap_Version2(id,Category,Query,Label,Status,URL);


}
    /**
     * This methods sends the V1 trap to the definded adress in port 162
     * @param id
     * @param Category
     * @param Query
     * @param Label
     * @param Status
     * @param URL
     */
    public void sendTrap_Version1(Variable id, Variable Category, Variable Query, Variable Label , Variable Status, Variable URL) {
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

            pdu.add(new VariableBinding(oid1,id));
            pdu.add(new VariableBinding(oid2,Category));
            pdu.add(new VariableBinding(oid3,Query));
            pdu.add(new VariableBinding(oid4,Label));
            pdu.add(new VariableBinding(oid5,Status));
            pdu.add(new VariableBinding(oid6,URL));
            // Send the PDU
            Snmp snmp = new Snmp(transport);
            System.out.println("Sending V1 Trap... Check Wheather NMS is Listening or not? ");
            snmp.send(pdu, cTarget);
            snmp.close();
        } catch (Exception e) {
            e.printStackTrace();
        }

    }
    public void sendTrap_Version2(Variable id, Variable Category, Variable Query, Variable Label , Variable Status, Variable URL) {
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

            OID oid = new OID(".1.3.6.1.4.1.50966.1.1");
            trap.add(new VariableBinding(SnmpConstants.snmpTrapOID, oid));
            trap.add(new VariableBinding(SnmpConstants.sysUpTime, new TimeTicks(5000))); // put your uptime here
            trap.add(new VariableBinding(SnmpConstants.sysDescr, new OctetString("description")));





           // trap.add(new VariableBinding(oid, "p"));
            //Add Payload

            trap.add(new VariableBinding(oid1, id));
            trap.add(new VariableBinding(oid2,Category));
            trap.add(new VariableBinding(oid3, Query));
            trap.add(new VariableBinding(oid4, Label));
            trap.add(new VariableBinding(oid5,Status));
            trap.add(new VariableBinding(oid6, URL));

            // Send the PDU
            Snmp snmp = new Snmp(transport);
            System.out.println("Sending  Trapv2  to "+ipAddress);
            snmp.send(trap, cTarget);
            snmp.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    public void sendTrap_Version3(Variable id, Variable Category, Variable Query, Variable Label , Variable Status, Variable URL) {
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
            pdu.add(new VariableBinding(new OID(oid1), new OctetString(
                    id.toString())));
            pdu.add(new VariableBinding(new OID(oid2), new OctetString(
                    Category.toString())));
            pdu.add(new VariableBinding(new OID(oid3), new OctetString(
                    Query.toString())));
            pdu.add(new VariableBinding(new OID(oid4), new OctetString(
                    Label.toString())));
            pdu.add(new VariableBinding(new OID(oid5), new OctetString(
                    Status.toString())));
            pdu.add(new VariableBinding(new OID(oid6), new OctetString(
                    URL.toString())));

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
