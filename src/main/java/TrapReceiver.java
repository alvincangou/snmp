import com.snmp4j.smi.SmiManager;
import com.snmp4j.smi.SmiParseException;
import org.snmp4j.PDU;
import org.snmp4j.Snmp;
import org.snmp4j.TransportMapping;
import org.snmp4j.agent.request.SnmpRequest;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.log.LogFactory;
import org.snmp4j.mp.MPv1;
import org.snmp4j.mp.MPv2c;
import org.snmp4j.mp.StateReference;
import org.snmp4j.mp.StatusInformation;
import org.snmp4j.security.Priv3DES;
import org.snmp4j.security.SecurityProtocols;
import org.snmp4j.smi.*;
import org.snmp4j.transport.AbstractTransportMapping;
import org.snmp4j.transport.DefaultTcpTransportMapping;
import org.snmp4j.transport.DefaultUdpTransportMapping;
import org.snmp4j.*;
import org.snmp4j.util.MultiThreadedMessageDispatcher;
import org.snmp4j.util.ThreadPool;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Iterator;
import java.util.Vector;

public class TrapReceiver implements CommandResponder
{
    static Agent agent;
    public static void main(String[] args) {
        try {

            // Compile the MIB modules in a MIB file:
            SmiManager smiManager = new SmiManager("63 15 2d 25 64 6d 71 33 / 2YB4Ci2l", new File("C:/Users/CFAPAG/empty/"));
            String[] moduleNames = smiManager.compile(new File("C:/MIB.txt"));

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
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        TrapReceiver snmp4jTrapReceiver = new TrapReceiver();
        try {
            snmp4jTrapReceiver.listen("0.0.0.0/162");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Trap Listner
     */

    public synchronized void listen(String address)
            throws IOException {

        AbstractTransportMapping transport;
        agent= new Agent("0.0.0.0/162");
        agent.start();
       /* if (address instanceof TcpAddress) {
            transport = new DefaultTcpTransportMapping((TcpAddress) address);
        } else {
            transport = new DefaultUdpTransportMapping((UdpAddress) address);
        }*/

      //  ThreadPool threadPool = ThreadPool.create("DispatcherPool", 10);
      //  MessageDispatcher mDispathcher = new MultiThreadedMessageDispatcher(
       //         threadPool, new MessageDispatcherImpl());

        // add message processing models
    //    mDispathcher.addMessageProcessingModel(new MPv1());
     //   mDispathcher.addMessageProcessingModel(new MPv2c());

        // add all security protocols
    //   SecurityProtocols.getInstance().addDefaultProtocols();
    //  SecurityProtocols.getInstance().addPrivacyProtocol(new Priv3DES());

        // Create Target
   //    CommunityTarget target = new CommunityTarget();
    //    target.setCommunity(new OctetString("public"));

      //  Snmp snmp = new Snmp( transport);
        //snmp.addCommandResponder(this);
agent.getSession().addCommandResponder(this);
        //transport.listen();
        agent.getSession().listen();
        System.out.println("Listening on " + address);

        try {
            this.wait();
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
//+agent.stop();
        }

    }

    /**
     * This method will be called whenever a pdu is received on the given port
     * specified in the listen() method
     */
    public synchronized void processPdu(CommandResponderEvent cmdRespEvent) {
        System.out.println("Received PDU...");
        PDU pdu = cmdRespEvent.getPDU();
        if (pdu != null) {
            System.out.println("Trap Type = " + pdu.getType());
            System.out.println("Variables = " + pdu.getVariableBindings());
        }
    }

 /*   public TrapReceiver()
    {
    }

    public static void main(String[] args)
    {
        TrapReceiver snmp4jTrapReceiver = new TrapReceiver();
        try {
            agent = new Agent("0.0.0.0/2001");
        } catch (IOException e) {
            e.printStackTrace(); System.err.println("Error in Listening for Trap");
        }

        try {
            agent.start();
        } catch (IOException e) {
            e.printStackTrace();  System.err.println("Error in Listening for Trap");
        }
        try {
            snmp4jTrapReceiver.listen();
        } catch (IOException e) {
            e.printStackTrace();
        }


    }

    *//**
     * This method will listen for traps and response pdu's from SNMP agent.
     *//*
    public synchronized void listen() throws IOException
    {



         TransportMapping   transport = new DefaultUdpTransportMapping(new UdpAddress("0.0.0.0/2000"));


        ThreadPool threadPool = ThreadPool.create("DispatcherPool", 10);
        MessageDispatcher mtDispatcher = new MultiThreadedMessageDispatcher(threadPool, new MessageDispatcherImpl());





        Snmp snmp = new Snmp(mtDispatcher, transport);
        snmp.addCommandResponder(this);

        transport.listen();
        System.out.println("Listening on " + "0.0.0.0/2001");

        try
        {
            this.wait();
        }
        catch (InterruptedException ex)
        {
            Thread.currentThread().interrupt();
        }
    }

    *//**
     * This method will be called whenever a pdu is received on the given port specified in the listen() method
     *//*
    public synchronized void processPdu(CommandResponderEvent cmdRespEvent)
    {
        System.out.println("Received PDU...");
        PDU pdu = cmdRespEvent.getPDU();
        if (pdu != null)
        {

            System.out.println("Trap Type = " + pdu.getType());
            System.out.println("Variable Bindings = " + pdu.getVariableBindings());
            int pduType = pdu.getType();
            if ((pduType != PDU.TRAP) && (pduType != PDU.V1TRAP) && (pduType != PDU.REPORT)
                    && (pduType != PDU.RESPONSE))
            {
                pdu.setErrorIndex(0);
                pdu.setErrorStatus(0);
                pdu.setType(PDU.RESPONSE);
                StatusInformation statusInformation = new StatusInformation();
                StateReference ref = cmdRespEvent.getStateReference();
                try
                {
                    System.out.println(cmdRespEvent.getPDU());
                    cmdRespEvent.getMessageDispatcher().returnResponsePdu(cmdRespEvent.getMessageProcessingModel(),
                            cmdRespEvent.getSecurityModel(), cmdRespEvent.getSecurityName(), cmdRespEvent.getSecurityLevel(),
                            pdu, cmdRespEvent.getMaxSizeResponsePDU(), ref, statusInformation);
                }
                catch (MessageException ex)
                {
                    System.err.println("Error while sending response: " + ex.getMessage());
                    LogFactory.getLogger(SnmpRequest.class).error(ex);
                }
            }
        }
    }*/
}