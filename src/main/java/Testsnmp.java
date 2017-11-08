import com.snmp4j.smi.SmiManager;
import com.snmp4j.smi.SmiParseException;
import org.junit.Test;

import java.io.File;
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
      //TODO here we delete evry data in the OID s
     //     agent.unregisterManagedObject(agent.getSnmpv2MIB());

        // Register a system description, use one from you product environment
        // to test with

//TODO here we regsiter what will be in the selected OID aka sysDescr and we put MySystemDescr in it the goal now is to creat private OID and put our information in it if we put ".1.3.6.1.4"(for private oid)we don't get shit because ther is nothing in it puting a value in it aferward work but its not in an official place
    //    agent.registerManagedObject(MOScalarFactory.createReadOnly(sysDescr,"MySystemDescr"));

        // Setup the client to use our newly started agent
        client = new SimpleSnmpClient("udp:127.0.0.1/2001");

      try {

          // Compile the MIB modules in a MIB file:
          SmiManager smiManager = new SmiManager("63 15 2d 25 64 6d 71 33 / 2YB4Ci2l", new File("/home/acangou/empty/"));
          String[] moduleNames = smiManager.compile(new File("/home/acangou/MIB.txt"));

          // Load compiled MIB modules into memory:
          for (String moduleName : moduleNames) {
              smiManager.loadModule(moduleName);

          }
          for (String a:smiManager.getLoadedModuleNames()
                  ) {
              System.out.println(a);

          }

      } catch (SmiParseException pex) {
          pex.printStackTrace();
      }
    }

    @AfterClass
    public static void tearDown() throws Exception {
        agent.stop();

        client.stop();
    }

    @Test


    public void verifySysDescr() throws IOException {
        assertEquals("SNMP4J-Agent - Linux - amd64 - 3.19.0-32-generic", client.getAsString(sysDescr));
       // client.sendTrap(system);
    }
    @Test


    public void sendtrap() throws IOException {



        // Create PDU
        PDU trap = new PDU();
        trap.setType(PDU.NOTIFICATION);
       OID oid  = new OID (".1.3.6.1.4.1.50966.1.1");
       OID oid1 = new OID(".1.3.6.1.4.1.50966.1.1.1");
       OID oid2 = new OID(".1.3.6.1.4.1.50966.1.1.2");
       OID oid3 = new OID(".1.3.6.1.4.1.50966.1.1.3");
       OID oid4 = new OID(".1.3.6.1.4.1.50966.1.1.4");
       OID oid5 = new OID(".1.3.6.1.4.1.50966.1.1.5");
       OID oid6 = new OID(".1.3.6.1.4.1.50966.1.1.6");


        trap.add(new VariableBinding(SnmpConstants.snmpTrapOID, oid));
        trap.add(new VariableBinding(SnmpConstants.sysUpTime, new TimeTicks(5000))); // put your uptime here
        trap.add(new VariableBinding(SnmpConstants.sysDescr, new OctetString("description")));


        //Add Payload
        Variable var = new OctetString("some string");
        trap.add(new VariableBinding(oid1, var));
        trap.add(new VariableBinding(oid2, var));
        trap.add(new VariableBinding(oid3, var));
        trap.add(new VariableBinding(oid4, var));
        trap.add(new VariableBinding(oid5, var));
        trap.add(new VariableBinding(oid6, var));
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
