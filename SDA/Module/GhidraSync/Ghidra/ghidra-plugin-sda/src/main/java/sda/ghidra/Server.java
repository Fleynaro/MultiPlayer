package sda.ghidra;

import org.apache.thrift.TException;
import org.apache.thrift.TMultiplexedProcessor;
import org.apache.thrift.server.TServer;
import org.apache.thrift.server.TSimpleServer;
import org.apache.thrift.transport.TServerSocket;
import org.apache.thrift.transport.TServerTransport;
import sda.Sda;
import sda.ghidra.datatype.*;
import sda.ghidra.function.FunctionManagerService;
import sda.ghidra.function.SFunction;
import sda.managers.DataTypeManager;
import sda.managers.FunctionManager;
import sda.util.DebugConsole;

import java.util.List;
import java.util.Map;

class DataTypeManagerHandler implements DataTypeManagerService.Iface
{
    private DataTypeManager manager;

    public DataTypeManagerHandler(DataTypeManager manager)
    {
        this.manager = manager;
    }

    @Override
    public List<SDataTypeBase> pull() throws TException {
        return manager.getAllTypes();
    }

    @Override
    public List<SDataTypeTypedef> pullTypedefs(Map<Long, Long> hashmap) throws TException {
        return manager.getAllTypedefs(hashmap);
    }

    @Override
    public List<SDataTypeStructure> pullStructures(Map<Long, Long> hashmap) throws TException {
        return manager.getAllStructures(hashmap);
    }

    @Override
    public List<SDataTypeEnum> pullEnums(Map<Long, Long> hashmap) throws TException {
        return manager.getAllEnums(hashmap);
    }

    @Override
    public void push(List<SDataType> types) throws TException {
        manager.change_commit(types);
    }

    @Override
    public void pushTypedefs(List<SDataTypeTypedef> typedefs) throws TException {
        manager.changeTypedefs_commit(typedefs);
    }

    @Override
    public void pushStructures(List<SDataTypeStructure> structures) throws TException {
        manager.changeStructure_commit(structures);
    }

    @Override
    public void pushEnums(List<SDataTypeEnum> enums) throws TException {
        manager.changeEnum_commit(enums);
    }
}

class FunctionManagerHandler implements FunctionManagerService.Iface
{
    private FunctionManager manager;

    public FunctionManagerHandler(FunctionManager manager)
    {
        this.manager = manager;
    }

    @Override
    public List<SFunction> pull(Map<Long, Long> hashmap) throws TException {
        return manager.getAllFunctions(hashmap);
    }

    @Override
    public void push(List<SFunction> functions) throws TException {
        manager.change_commit(functions);
    }
}

public class Server {
    private Sda sda;
    private TMultiplexedProcessor processor;
    private Thread workingThread;
    private TServer server;
    private int port = 9090;

    public Server(Sda sda, int port)
    {
        this.sda = sda;
        this.port = port;
        createMultiplexedProcessor();
        createWorkingThread();
    }

    public void start()
    {
        workingThread.start();
    }

    public void stop()
    {
        server.stop();
    }

    private void createMultiplexedProcessor()
    {
        processor = new TMultiplexedProcessor();
        processor.registerProcessor(
                "DataTypeManager",
                new DataTypeManagerService.Processor(new DataTypeManagerHandler(sda.getDataTypeManager())));
        processor.registerProcessor(
                "FunctionManager",
                new FunctionManagerService.Processor(new FunctionManagerHandler(sda.getFunctionManager())));
    }

    private void createWorkingThread()
    {
        Runnable server = new Runnable() {
            public void run() {
                work();
            }
        };

        workingThread = new Thread(server);
    }

    private void work() {
        try {
            TServerTransport serverTransport = new TServerSocket(port);
            server = new TSimpleServer(new TServer.Args(serverTransport).processor(processor));
            DebugConsole.info(this, "Starting the simple server...");
            server.serve();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
