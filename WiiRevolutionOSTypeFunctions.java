// Adds type information to lots of system routines.
// See: https://wiibrew.org/wiki/Revolution_OS 🥳
//@author 
//@category Wii
//@keybinding 
//@menupath 
//@toolbar 
//@runtime Java

import java.util.List;

import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.data.*;

public class WiiRevolutionOSTypeFunctions extends GhidraScript {

    @Override
    public void run() throws Exception {
        createFunctionDataType("void* OSInterruptHandler(void)");
        createFunctionDataType("void* OSThreadMain(void* arg)");

        typeAndCommentFunction("OSGetConsoleType", "int OSGetConsoleType(void)",
            "Returns the platform ID.");
        typeAndCommentFunction("OSInit", "void OSInit(void)",
            "Initializes all parts of the library.");
        typeAndCommentFunction("OSSaveFPUContext", "void OSSaveFPUContext(OSContext *ctx)",
            "Saves the floating point registers to ctx.");
        typeAndCommentFunction("OSSetCurrentContext", "void OSSetCurrentContext(OSContext *ctx)",
            "Sets the context to ctx, causing future register saving to go there.");
        typeAndCommentFunction("OSGetCurrentContext", "OSContext *OSGetCurrentContext(void)",
            "Gets the OSContext instance currently being used (not the floating point one).");
        typeAndCommentFunction("OSSaveContext", "bool OSSaveContext(OSContext *ctx)",
            "Saves nonessential registers to ctx. Returns true if the function is returning after ctx was reloaded back to the state, which was saved as being in this function.");
        typeAndCommentFunction("OSLoadContext", "void OSLoadContext(OSContext *ctx)",
            "Loads the registers in ctx. Ensures OSDisableInterrupts runs atomically to prevent MSR corruption.");
        typeAndCommentFunction("OSGetStackPointer", "void *OSGetStackPointer(void)",
            "Returns the current stack pointer.");
        typeAndCommentFunction("OSSwitchFiber", "void OSSwitchFiber(void *code, void *stack)",
            "Swaps the stack and jumps to code.");
        typeAndCommentFunction("OSSwitchFiberEx",
            "void OSSwitchFiberEx(int param1, int param2, int param3, int param4, void *code, void *stack)",
            "Swaps the stack and jumps to code, passing up to 4 args.");
        typeAndCommentFunction("OSClearContext", "void OSClearContext(OSContext *ctx)",
            "Marks ctx as having nothing saved to it.");
        typeAndCommentFunction("OSInitContext", "void OSInitContext(OSContext *ctx)",
            "Sets all saved registers in ctx to 0.");
        typeAndCommentFunction("OSDumpContext", "void OSDumpContext(OSContext *ctx)",
            "Prints all saved registers in ctx.");
        typeAndCommentFunction("OSReport", "void OSReport(char *format, ...)",
            "Calls vprintf; the formatted text gets sent through some MetroTRK-related SerialIO port.");
        typeAndCommentFunction("OSPanic",
            "void OSPanic(char *sourceFile, int lineNo, char *format, ...)",
            "Prints the message similar to OSReport, then prints the crash location and a stack trace.");
        typeAndCommentFunction("OSDisableInterrupts", "bool OSDisableInterrupts(void)",
            "Disables interrupts, allowing code to run atomically. Returns the previous interrupt state for a call to OSRestoreInterrupts.");
        typeAndCommentFunction("OSEnableInterrupts", "bool OSEnableInterrupts(void)",
            "Enables interrupts, returning the previous interrupt state. Use with care, as it may have unintended effects if a calling function disabled interrupts.");
        typeAndCommentFunction("OSRestoreInterrupts",
            "bool OSRestoreInterrupts(bool interruptState)",
            "Sets the interrupt state to the state specified by the parameter. Typically used at the end of an atomic segment. Returns the previous interrupt state.");
        typeAndCommentFunction("__OSSetInterruptHandler",
            "OSInterruptHandler* OSSetInterruptHandler(int interrupt, OSInterruptHandler *handler)",
            "Sets the handler for a particular interrupt, returning the old handler.");
        typeAndCommentFunction("__OSGetInterruptHandler",
            "OSInterruptHandler* OSGetInterruptHandler(int interrupt)",
            "Reads the appropriate handler from a table.");
        typeAndCommentFunction("OSInitMessageQueue",
            "void OSInitMessageQueue(OSMessageQueue *queue, int *buf, int capacity)",
            "Initializes the fields of the OSMessageQueue.");
        typeAndCommentFunction("OSSendMessage",
            "bool OSSendMessage(OSMessageQueue *queue, int msg, bool waitForSpace)",
            "Adds a message to the end of the queue. Returns whether this was successful.");
        typeAndCommentFunction("OSReceiveMessage",
            "bool OSReceiveMessage(OSMessageQueue *queue, int *msg, bool waitForMsg)",
            "Removes a message from the front of the queue, returning whether the operation was successful.");
        typeAndCommentFunction("OSJamMessage",
            "bool OSJamMessage(OSMessageQueue *queue, int msg, bool waitForSpace)",
            "Adds a message to the front of the queue. Returns whether this was successful.");
        typeAndCommentFunction("OSGetPhysicalMem1Size", "int OSGetPhysicalMem1Size(void)",
            "Reads the MEM1 size from lomem.");
        typeAndCommentFunction("OSGetPhysicalMem2Size", "int OSGetPhysicalMem2Size(void)",
            "Reads the MEM2 size from lomem.");
        typeAndCommentFunction("OSGetConsoleSimulatedMem1Size",
            "int OSGetConsoleSimulatedMem1Size(void)", "Reads the simulated MEM1 size from lomem.");
        typeAndCommentFunction("OSGetConsoleSimulatedMem2Size",
            "int OSGetConsoleSimulatedMem2Size(void)", "Reads the simulated MEM2 size from lomem.");
        typeAndCommentFunction("OSInitMutex", "void OSInitMutex(OSMutex *mutex)",
            "Initializes the fields of a mutex.");
        typeAndCommentFunction("OSLockMutex", "void OSLockMutex(OSMutex *mutex)",
            "Locks a mutex, blocking if needed. Supports recursive locking.");
        typeAndCommentFunction("OSUnlockMutex", "void OSUnlockMutex(OSMutex *mutex)",
            "Unlocks a mutex. Supports recursive locking.");
        typeAndCommentFunction("OSTryLockMutex", "bool OSTryLockMutex(OSMutex *mutex)",
            "Attempts to lock a mutex, returning whether the operation was successful.");
        typeAndCommentFunction("OSYieldThread", "void OSYieldThread(void)",
            "Switches to another thread.");
        typeAndCommentFunction("OSCreateThread",
            "bool OSCreateThread(OSThread *thread, OSThreadMain* main, void *arg, void *stackPtr, int stackSize, int priority, bool detached)",
            "Creates and starts a thread using the given OSThread.");
        typeAndCommentFunction("OSCancelThread", "void OSCancelThread(OSThread *thread)",
            "Stops a thread.");
        typeAndCommentFunction("OSSleepThread", "void OSSleepThread(OSThreadQueue *waitingQueue)",
            "Pauses the current thread until OSResumeThread is called with this thread queue.");
        typeAndCommentFunction("OSResumeThread", "void OSResumeThread(OSThreadQueue *waitingQueue)",
            "Resumes all threads in the queue.");
    }

    private void typeAndCommentFunction(String functionName, String signature, String comment)
            throws Exception {
        println("Setting signature and comment for function: " + functionName);

        List<Function> functions = getGlobalFunctions(functionName);
        functions.addAll(getGlobalFunctions("__" + functionName));

        for (var function : functions) {
            applySignature(function, signature);
            function.setComment(comment);
        }

        if (functions.size() == 0) {
            println("Function not found: " + functionName);
        }
    }

    // Add a function datatype to the current program's DataTypeManager.
    private void createFunctionDataType(String signature) throws Exception {
        // Get the current program's DataTypeManager
        DataTypeManager dtm = currentProgram.getDataTypeManager();

        // Create a FunctionDefinitionDataType from the signature
        FunctionSignatureParser parser =
            new FunctionSignatureParser(dtm, null);
        FunctionDefinitionDataType functionDefinition =
            parser.parse(null, signature);
        functionDefinition.setCallingConvention("__stdcall"); // Set the calling convention to __stdcall

        // Add the new function DataType to the DataTypeManager
        dtm.addDataType(functionDefinition,
                    DataTypeConflictHandler.REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER);
    }

    private void applySignature(Function function, String signature) throws Exception {
        FunctionSignatureParser parser =
            new FunctionSignatureParser(currentProgram.getDataTypeManager(), null);
        FunctionDefinitionDataType functionDefinition = parser.parse(null, signature);
        currentProgram.getDataTypeManager()
                .addDataType(functionDefinition,
                    DataTypeConflictHandler.REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER);
        ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(function.getEntryPoint(),
            functionDefinition, SourceType.USER_DEFINED);
        cmd.applyTo(currentProgram);
    }
}