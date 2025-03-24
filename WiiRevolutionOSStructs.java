// Defines structures used by RevolutionOS
// See https://wiibrew.org/wiki/Revolution_OS 🥳
//@author 
//@category Wii
//@keybinding 
//@menupath 
//@toolbar 
//@runtime Java

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;

public class WiiRevolutionOSStructs extends GhidraScript {

    @Override
    public void run() throws Exception {
        defineOSContext();
        defineOSThread();
        defineOSThreadQueue();
        defineOSThreadLink();
        defineOSMutex();
        defineOSMutexQueue();
        defineOSThreadInfo();
        defineOSHeapCell();
        defineOSHeapData();
        defineOSMessageQueue();
        defineOSShutdownFunction();
    }

    private void defineOSContext() throws Exception {
        StructureDataType struct = new StructureDataType("OSContext", 0);
        struct.add(new ArrayDataType(DWordDataType.dataType, 0x20, DWordDataType.dataType.getLength()), "gprs", "r0-r31");
        struct.add(DWordDataType.dataType, "cr", "0x80");
        struct.add(DWordDataType.dataType, "lr", "0x84");
        struct.add(DWordDataType.dataType, "ctr", "0x88");
        struct.add(DWordDataType.dataType, "xer", "0x8c");
        struct.add(new ArrayDataType(QWordDataType.dataType, 0x20, QWordDataType.dataType.getLength()), "fprs", "f0-f31");
        struct.add(QWordDataType.dataType, "fpscr", "0x190");
        struct.add(DWordDataType.dataType, "srr0", "0x198 - saved PC");
        struct.add(DWordDataType.dataType, "srr1", "0x19c - saved MSR");
        struct.add(WordDataType.dataType, "state", "0x1a2; last bit means OSSaveFPUContext was called, second last bit means the GPRs were saved by the exception handler");
        struct.add(new ArrayDataType(QWordDataType.dataType, 4, QWordDataType.dataType.getLength()), "gqrs", "0x1a4");
        struct.add(new ArrayDataType(QWordDataType.dataType, 0x20, QWordDataType.dataType.getLength()), "pairedSingles", "starting at 0x1c8");
        createDataType(struct);
    }

    private void defineOSThread() throws Exception {
        StructureDataType struct = new StructureDataType("OSThread", 0);
        struct.add(new PointerDataType(new StructureDataType("OSContext", 0)), "ctx", null);
        struct.add(WordDataType.dataType, "state", "0x2c8; 0 = stopped, 1 = inactive, 2 = active, 4 = sleeping, 8 = returned result?");
        struct.add(WordDataType.dataType, "detached", "0x2ca; zero = false, nonzero = true");
        struct.add(DWordDataType.dataType, "suspend", "seems to be a balancing counter. 0 = active, 1 = suspended");
        struct.add(DWordDataType.dataType, "priority", "0x2d0; can range from 0-31");
        struct.add(DWordDataType.dataType, "basePriority", "0x2d4");
        struct.add(DWordDataType.dataType, "returnValue", "0x2d8");
        struct.add(new PointerDataType(new StructureDataType("OSThreadQueue", 0)), "queue", "0x2dc");
        struct.add(new StructureDataType("OSThreadLink", 0), "linkQueue", "0x2e0");
        struct.add(new StructureDataType("OSThreadQueue", 0), "queueJoin", "0x2e8");
        struct.add(new PointerDataType(new StructureDataType("OSMutex", 0)), "mutex", "0x2f0; mutex currently waiting for; used for deadlock detection");
        struct.add(new StructureDataType("OSMutexQueue", 0), "queueMutex", "0x2f4");
        struct.add(new StructureDataType("OSThreadLink", 0), "linkActive", "0x2fc");
        struct.add(new PointerDataType(VoidDataType.dataType), "stackStart", "0x304");
        struct.add(new PointerDataType(VoidDataType.dataType), "stackEnd", "0x308");
        struct.add(DWordDataType.dataType, "unknown", "0x30c");
        struct.add(new ArrayDataType(DWordDataType.dataType, 2, DWordDataType.dataType.getLength()), "threadSpecifics", "0x310");
        createDataType(struct);
    }

    private void defineOSThreadQueue() throws Exception {
        StructureDataType struct = new StructureDataType("OSThreadQueue", 0);
        struct.add(new PointerDataType(new StructureDataType("OSThread", 0)), "head", null);
        struct.add(new PointerDataType(new StructureDataType("OSThread", 0)), "tail", null);
        createDataType(struct);
    }

    private void defineOSThreadLink() throws Exception {
        StructureDataType struct = new StructureDataType("OSThreadLink", 0);
        struct.add(new PointerDataType(new StructureDataType("OSThread", 0)), "next", null);
        struct.add(new PointerDataType(new StructureDataType("OSThread", 0)), "prev", null);
        createDataType(struct);
    }

    private void defineOSMutex() throws Exception {
        StructureDataType struct = new StructureDataType("OSMutex", 0);
        struct.add(new StructureDataType("OSThreadQueue", 0), "waitingQueue", null);
        struct.add(new PointerDataType(new StructureDataType("OSThread", 0)), "holder", null);
        struct.add(DWordDataType.dataType, "timesLocked", "used if a mutex is locked multiple times by the same thread");
        struct.add(new PointerDataType(new StructureDataType("OSMutex", 0)), "next", null);
        struct.add(new PointerDataType(new StructureDataType("OSMutex", 0)), "prev", null);
        createDataType(struct);
    }

    private void defineOSMutexQueue() throws Exception {
        StructureDataType struct = new StructureDataType("OSMutexQueue", 0);
        struct.add(new PointerDataType(new StructureDataType("OSMutex", 0)), "head", null);
        struct.add(new PointerDataType(new StructureDataType("OSMutex", 0)), "tail", null);
        createDataType(struct);
    }

    private void defineOSThreadInfo() throws Exception {
        StructureDataType struct = new StructureDataType("OSThreadInfo", 0);
        struct.add(new StructureDataType("OSThread", 0), "initialThread", null);
        struct.add(new ArrayDataType(new StructureDataType("OSThreadQueue", 0), 0x20, new StructureDataType("OSThreadQueue", 0).getLength()), "RunQueue", null);
        struct.add(new StructureDataType("OSContext", 0), "idleCtx", null);
        createDataType(struct);
    }

    private void defineOSHeapCell() throws Exception {
        StructureDataType struct = new StructureDataType("OSHeapCell", 0);
        struct.add(new PointerDataType(new StructureDataType("OSHeapCell", 0)), "prev", null);
        struct.add(new PointerDataType(new StructureDataType("OSHeapCell", 0)), "next", null);
        struct.add(DWordDataType.dataType, "size", null);
        struct.add(new ArrayDataType(ByteDataType.dataType, 0x14, ByteDataType.dataType.getLength()), "unknown", null);
        createDataType(struct);
    }

    private void defineOSHeapData() throws Exception {
        StructureDataType struct = new StructureDataType("OSHeapData", 0);
        struct.add(DWordDataType.dataType, "size", null);
        struct.add(new PointerDataType(new StructureDataType("OSHeapCell", 0)), "free", null);
        struct.add(new PointerDataType(new StructureDataType("OSHeapCell", 0)), "allocated", null);
        createDataType(struct);
    }

    private void defineOSMessageQueue() throws Exception {
        StructureDataType struct = new StructureDataType("OSMessageQueue", 0);
        struct.add(new StructureDataType("OSThreadQueue", 0), "waitForSend", null);
        struct.add(new StructureDataType("OSThreadQueue", 0), "waitForReceive", null);
        struct.add(new PointerDataType(VoidDataType.dataType), "buf", null);
        struct.add(DWordDataType.dataType, "messageCapacity", null);
        struct.add(DWordDataType.dataType, "rotation", null);
        struct.add(DWordDataType.dataType, "messagesEnqueued", null);
        createDataType(struct);
    }

    private void defineOSShutdownFunction() throws Exception {
        StructureDataType struct = new StructureDataType("OSShutdownFunction", 0);
        struct.add(new PointerDataType(VoidDataType.dataType), "func", "2 params, unknown type");
        struct.add(DWordDataType.dataType, "priority", "lower priority goes first");
        struct.add(new PointerDataType(new StructureDataType("OSShutdownFunction", 0)), "next", null);
        struct.add(new PointerDataType(new StructureDataType("OSShutdownFunction", 0)), "prev", null);
        createDataType(struct);
    }

    private void createDataType(StructureDataType struct) throws Exception {
        DataTypeManager dtm = currentProgram.getDataTypeManager();

        class ReplaceConflictHandler extends DataTypeConflictHandler
        {
            @Override
            public ConflictResult resolveConflict(DataType addedDataType,
                    DataType existingDataType) {
                return ConflictResult.REPLACE_EXISTING;
            }

            @Override
            public boolean shouldUpdate(DataType sourceDataType, DataType localDataType) {
                return true;
            }

            @Override
            public DataTypeConflictHandler getSubsequentHandler() {
                return this;
            }
        }

        dtm.addDataType(struct, DataTypeConflictHandler.REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER);
    }
}