import org.junit.BeforeClass;
import org.junit.Test;
import org.snmp4j.agent.mo.MOAccessImpl;
import org.snmp4j.smi.*;
import sun.management.resources.agent;

import java.util.List;

import static org.junit.Assert.assertEquals;

public class Testtable {
    static Agent agent;
    static SimpleSnmpClient client;
    static final OID interfacesTable = new OID(".1.3.6.1.2.1.2.2.1");

    @BeforeClass
    public static void setUp() throws Exception {
        agent = new Agent("0.0.0.0/2001");
        agent.start();
        // Build a table. This example is taken from TestAgent and sets up
        // two physical interfaces
        MOTableBuilder builder = new MOTableBuilder(interfacesTable)
                .addColumnType(SMIConstants.SYNTAX_INTEGER, MOAccessImpl.ACCESS_READ_ONLY)
                .addColumnType(SMIConstants.SYNTAX_OCTET_STRING,MOAccessImpl.ACCESS_READ_ONLY)
                .addColumnType(SMIConstants.SYNTAX_INTEGER,MOAccessImpl.ACCESS_READ_ONLY)
                .addColumnType(SMIConstants.SYNTAX_INTEGER,MOAccessImpl.ACCESS_READ_ONLY)
                .addColumnType(SMIConstants.SYNTAX_GAUGE32,MOAccessImpl.ACCESS_READ_ONLY)
                .addColumnType(SMIConstants.SYNTAX_OCTET_STRING,MOAccessImpl.ACCESS_READ_ONLY)
                .addColumnType(SMIConstants.SYNTAX_INTEGER,MOAccessImpl.ACCESS_READ_ONLY)
                .addColumnType(SMIConstants.SYNTAX_INTEGER,MOAccessImpl.ACCESS_READ_ONLY)
                // Normally you would begin loop over you two domain objects here
                .addRowValue(new Integer32(1))
                .addRowValue(new OctetString("loopback"))
                .addRowValue(new Integer32(24))
                .addRowValue(new Integer32(1500))
                .addRowValue(new Gauge32(10000000))
                .addRowValue(new OctetString("00:00:00:00:01"))
                .addRowValue(new Integer32(1500))
                .addRowValue(new Integer32(1500))
                //next row
                .addRowValue(new Integer32(2))
                .addRowValue(new OctetString("eth0"))
                .addRowValue(new Integer32(24))
                .addRowValue(new Integer32(1500))
                .addRowValue(new Gauge32(10000000))
                .addRowValue(new OctetString("00:00:00:00:02"))
                .addRowValue(new Integer32(1500))
                .addRowValue(new Integer32(1500));

        agent.registerManagedObject(builder.build());

        // Setup the client to use our newly started agent
        client = new SimpleSnmpClient("udp:127.0.0.1/2001");
    }
    @Test
    public void verifyTableContents() {

        // You retreive a table by suppling the columns of the table that
        // you need, here we use column 2,6 and 8 so we do not verify the complete
        // table
        List<List<String>> tableContents = client.getTableAsStrings(new OID[]{
                new OID(interfacesTable.toString() + ".2"),
                new OID(interfacesTable.toString() + ".6"),
                new OID(interfacesTable.toString() + ".8")});

        //and validate here
        assertEquals(2, tableContents.size());
        assertEquals(3, tableContents.get(0).size());
        assertEquals(3, tableContents.get(1).size());

        // Row 1
        assertEquals("loopback", tableContents.get(0).get(0));
        assertEquals("00:00:00:00:01", tableContents.get(0).get(1));
        assertEquals("1500", tableContents.get(0).get(2));
        // Row 2
        assertEquals("eth0", tableContents.get(1).get(0));
        assertEquals("00:00:00:00:02", tableContents.get(1).get(1));
        assertEquals("1500", tableContents.get(1).get(2));
    }
}
