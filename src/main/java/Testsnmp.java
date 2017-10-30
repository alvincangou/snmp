import org.junit.Test;

import java.io.IOException;
import java.net.UnknownHostException;
import java.util.Iterator;
import java.util.List;
import java.util.Vector;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.snmp4j.mp.SnmpConstants.sysDescr;

import org.junit.*;
import org.snmp4j.*;
import org.snmp4j.agent.MOScope;
import org.snmp4j.agent.ManagedObject;
import org.snmp4j.agent.mo.MOAccessImpl;
import org.snmp4j.agent.request.SubRequest;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.event.ResponseListener;
import org.snmp4j.mp.MPv1;
import org.snmp4j.mp.MPv2c;
import org.snmp4j.mp.MPv3;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.security.*;
import org.snmp4j.smi.*;
import org.snmp4j.transport.AbstractTransportMapping;
import org.snmp4j.transport.DefaultTcpTransportMapping;
import org.snmp4j.transport.DefaultUdpTransportMapping;
import org.snmp4j.util.MultiThreadedMessageDispatcher;
import org.snmp4j.util.ThreadPool;

public class Testsnmp {
private boolean result;
    private Snmp snmp = null;
    private Address listenAddress;
    private ThreadPool threadPool;
    private  MultiThreadedMessageDispatcher dispatcher;
    private int n = 0;
    private long start = -1;
    static Agent agent;
    static Agent agent2;
    static SimpleSnmpClient client;
    static final OID sysDescr = new OID(".1.3.6.1.2.1.1.1.0");

  @BeforeClass
    public static void setUp() throws Exception {
        agent = new Agent("0.0.0.0/2001");

        agent.start();

        // Since BaseAgent registers some mibs by default we need to unregister
        // one before we register our own sysDescr. Normally you would
        // override that method and register the mibs that you need
          agent.unregisterManagedObject(agent.getSnmpv2MIB());

        // Register a system description, use one from you product environment
        // to test with


        agent.registerManagedObject(MOScalarFactory.createReadOnly(sysDescr,"MySystemDescr"));

        // Setup the client to use our newly started agent
        client = new SimpleSnmpClient("udp:127.0.0.1/2001");
    }

    @AfterClass
    public static void tearDown() throws Exception {
        agent.stop();

        client.stop();
    }

    @Test


    public void verifySysDescr() throws IOException {
        assertEquals("MySystemDescr", client.getAsString(sysDescr));
       // client.sendTrap(system);
    }
    @Test


    public void sendtrap() throws IOException {

        // Create PDU
        PDU trap = new PDU();
        trap.setType(PDU.TRAP);

        OID oid = new OID(".1.3.6.1.2.1.1.1.0");
        trap.add(new VariableBinding(SnmpConstants.snmpTrapOID, oid));
        trap.add(new VariableBinding(SnmpConstants.sysUpTime, new TimeTicks(5000))); // put your uptime here
        trap.add(new VariableBinding(SnmpConstants.sysDescr, new OctetString("System Description")));

        //Add Payload
        Variable var = new OctetString("some string");
        trap.add(new VariableBinding(oid, var));

        // Specify receiver
        Address targetaddress = new UdpAddress("127.0.0.1/2001");
        CommunityTarget target = new CommunityTarget();
        target.setCommunity(new OctetString("public"));
        target.setVersion(SnmpConstants.version2c);
        target.setAddress(targetaddress);





     //  AbstractTransportMapping transport = new DefaultUdpTransportMapping((UdpAddress)new UdpAddress("0.0.0.0/2001"));
//CommunityTarget target1 = new CommunityTarget();
//target.setCommunity(new OctetString("public"));
         //snmp = new Snmp();


//Envoi du trap // Send

//Réception du trap


agent.getSession().addCommandResponder(new CommandResponder() {

    @Override
    public void processPdu(CommandResponderEvent event) {
        System.out.println("listening");
     /*   if (start < 0) {
            start = System.currentTimeMillis() - 1;
        }
        n++;
        if ((n % 100 == 1)) {
            System.out.println("Processed "
                    + (n / (double) (System.currentTimeMillis() - start))
                    * 1000 + "/s, total=" + n);
        }*/

        StringBuffer msg = new StringBuffer();
        msg.append(event.toString());
        Vector<? extends VariableBinding> varBinds = event.getPDU()
                .getVariableBindings();
        if (varBinds != null && !varBinds.isEmpty()) {


            Iterator<? extends VariableBinding> varIter = varBinds.iterator();
            while (varIter.hasNext()) {
                VariableBinding var = varIter.next();
                msg.append(var.toString()).append(";");
            }
        }

        System.out.println("Message Received: " + msg.toString());

    }
});
trap.getErrorStatus();
      agent.getSession().listen();
     //   transport.listen();
   agent.getSession().send(trap, target, null, null);
//agent.getSession().send(trap,target,null,null);
//Test Envoi=Réception

        assertTrue(true);

    }



}
