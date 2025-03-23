// Names global variables which are the same in all Wii applications.
// Lots of the constant names were sourced from https://wiibrew.org/wiki/Memory_map 🥳
//@author 
//@category Wii
//@keybinding 
//@menupath 
//@toolbar 
//@runtime Java

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.SourceType;

public class WiiGlobals extends GhidraScript {

    @Override
    public void run() throws Exception {
        Memory memory = currentProgram.getMemory();

        addAnnotation(memory, 0x80000000, "g_game_code", new ArrayDataType(new CharDataType(), 4),
            "Game Code 'RSPE' (Wii Sports)");
        addAnnotation(memory, 0x80000004, "g_maker_code", new UnsignedShortDataType(),
            "Maker code");
        addAnnotation(memory, 0x80000006, "g_disc_number", new ByteDataType(),
            "Disc Number (multidisc games)");
        addAnnotation(memory, 0x80000007, "g_disc_version", new ByteDataType(), "Disc Version");
        addAnnotation(memory, 0x80000008, "g_disc_streaming_flag", new ByteDataType(),
            "Disc Streaming flag");
        addAnnotation(memory, 0x80000009, "g_disc_streaming_buffer_size", new ByteDataType(),
            "Disc Streaming buffer size");
        addAnnotation(memory, 0x80000018, "g_disc_layout_magic_wii", new UnsignedIntegerDataType(),
            "Disc layout magic (Wii)");
        addAnnotation(memory, 0x8000001C, "g_disc_layout_magic_gc", new UnsignedIntegerDataType(),
            "Disc layout magic (GC)");
        addAnnotation(memory, 0x80000020, "g_nintendo_boot_code", new UnsignedIntegerDataType(),
            "Nintendo Standard Boot Code");
        addAnnotation(memory, 0x80000024, "g_version", new UnsignedIntegerDataType(),
            "Version (set by apploader)");
        addAnnotation(memory, 0x80000028, "g_memory_size", new UnsignedIntegerDataType(),
            "Memory Size (Physical) 24MB");
        addAnnotation(memory, 0x8000002C, "g_board_model", new UnsignedIntegerDataType(),
            "Production Board Model");
        addAnnotation(memory, 0x80000030, "g_arena_low", new UnsignedIntegerDataType(),
            "Arena Low");
        addAnnotation(memory, 0x80000034, "g_arena_high", new UnsignedIntegerDataType(),
            "Arena High");
        addAnnotation(memory, 0x80000038, "g_fst_start", new UnsignedIntegerDataType(),
            "Start of FST (varies in all games)");
        addAnnotation(memory, 0x8000003C, "g_fst_max_size", new UnsignedIntegerDataType(),
            "Maximum FST Size (varies in all games)");
        addAnnotation(memory, 0x80000040, "g_db_global_struct", new UnsignedIntegerDataType(),
            "Beginning of the DB global struct");
        addAnnotation(memory, 0x80000044, "g_db_exception_mask", new UnsignedIntegerDataType(),
            "DB marked exception mask");
        addAnnotation(memory, 0x80000048, "g_db_exception_dest", new UnsignedIntegerDataType(),
            "DB exception destination");
        addAnnotation(memory, 0x8000004C, "g_db_return_addr", new UnsignedIntegerDataType(),
            "DB return address");
        addAnnotation(memory, 0x80000060, "g_osdb_integrator_hook",
            new ArrayDataType(new ByteDataType(), 0x24, 1), "OSDBIntegrator Debugger Hook");
        addAnnotation(memory, 0x800000C0, "g_oscontext_real_mode", new UnsignedIntegerDataType(),
            "Current OSContext instance (real mode)");
        addAnnotation(memory, 0x800000C4, "g_user_interrupt_mask", new UnsignedIntegerDataType(),
            "User interrupt mask");
        addAnnotation(memory, 0x800000C8, "g_os_interrupt_mask", new UnsignedIntegerDataType(),
            "Revolution OS interrupt mask");
        addAnnotation(memory, 0x800000CC, "g_video_mode", new UnsignedIntegerDataType(),
            "Value indicating the current video mode. 0 = NTSC, 1 = PAL, 2 = MPAL");
        addAnnotation(memory, 0x800000D4, "g_oscontext_translated_mode",
            new UnsignedIntegerDataType(), "Current OSContext instance (translated mode)");
        addAnnotation(memory, 0x800000D8, "g_oscontext_fprs", new UnsignedIntegerDataType(),
            "OSContext to save FPRs to (NULL if floating point mode hasn't been used since the last interrupt)");
        addAnnotation(memory, 0x800000DC, "g_earliest_osthread", new UnsignedIntegerDataType(),
            "Pointer to the earliest created OSThread");
        addAnnotation(memory, 0x800000E0, "g_latest_osthread", new UnsignedIntegerDataType(),
            "Pointer to the most recently created OSThread");
        addAnnotation(memory, 0x800000E4, "g_current_osthread", new UnsignedIntegerDataType(),
            "Pointer to the current OSThread");
        addAnnotation(memory, 0x800000EC, "g_dev_debugger_monitor_addr",
            new UnsignedIntegerDataType(), "Dev Debugger Monitor Address (If present)");
        addAnnotation(memory, 0x800000F0, "g_simulated_memory_size", new UnsignedIntegerDataType(),
            "Simulated Memory Size");
        addAnnotation(memory, 0x800000F4, "g_partition_data_ptr", new UnsignedIntegerDataType(),
            "Pointer to data read from partition's bi2.bin, set by apploader, or the emulated bi2.bin created by the NAND Boot Program");
        addAnnotation(memory, 0x800000F8, "g_console_bus_speed", new UnsignedIntegerDataType(),
            "Console Bus Speed");
        addAnnotation(memory, 0x800000FC, "g_console_cpu_speed", new UnsignedIntegerDataType(),
            "Console CPU Speed");
        // TODO: Enable these when we have added a dataype for the exception handler, so we can make these arrays of
        // exception handlers instead of a big data blob which will obscure references to individual handlers.
        // addAnnotation(memory, 0x80000100, "g_exception_handlers",
        //     new ArrayDataType(new ByteDataType(), 0x1700, 1),
        //     "Exception handlers (0x100 bytes reserved for each handler)");
        // addAnnotation(memory, 0x80001800, "g_unused_exception_handler_area",
        //     new ArrayDataType(new ByteDataType(), 0x1800, 1),
        //     "Unused exception handler area, the SDK does not use or clear it. It is often used by homebrew to store persistent code here like Gecko OS's code handler, Bluebomb or The Homebrew Channel's reload stub, which libogc jumps to upon homebrew exit.");
        // addAnnotation(memory, 0x80003000, "g_exception_vector_area",
        //     new ArrayDataType(new ByteDataType(), 0x3c, 1), "Exception vector area");
        addAnnotation(memory, 0x80003040, "g_os_interrupt_table", new UnsignedIntegerDataType(),
            "__OSInterrupt table.");
        addAnnotation(memory, 0x800030C0, "g_exi_probe_start_times",
            new ArrayDataType(new UnsignedIntegerDataType(), 2, 4),
            "EXI Probe start times, for both channels 0 and 1.");
        addAnnotation(memory, 0x800030C8, "g_rel_first_loaded_file", new UnsignedIntegerDataType(),
            "Related to Nintendo's dynamic linking system (REL). Pointer to the first loaded REL file.");
        addAnnotation(memory, 0x800030CC, "g_rel_last_loaded_file", new UnsignedIntegerDataType(),
            "Related to Nintendo's dynamic linking system (REL). Pointer to the last loaded REL file.");
        addAnnotation(memory, 0x800030D0, "g_rel_module_name_table_ptr",
            new UnsignedIntegerDataType(),
            "Pointer to a REL module name table, or 0. Added to the name offset in each REL file.");
        addAnnotation(memory, 0x800030D8, "g_system_time",
            new ArrayDataType(new UnsignedIntegerDataType(), 2, 4),
            "System time, measured as time since January 1st 2000 in units of 1/40500000th of a second.");
        addAnnotation(memory, 0x800030E4, "g_os_pad_button", new UnsignedShortDataType(),
            "__OSPADButton. Apploader puts button state of GCN port 4 at game start here for Gamecube NR disc support");
        addAnnotation(memory, 0x800030E6, "g_dvd_device_code_addr", new UnsignedShortDataType(),
            "DVD Device Code Address");
        addAnnotation(memory, 0x800030E8, "g_debug_info", new UnsignedIntegerDataType(),
            "Debug-related info");
        addAnnotation(memory, 0x800030F0, "g_dol_execute_params", new UnsignedIntegerDataType(),
            "DOL Execute Parameters");
        addAnnotation(memory, 0x80003100, "g_physical_mem1_size", new UnsignedIntegerDataType(),
            "Physical MEM1 size");
        addAnnotation(memory, 0x80003104, "g_simulated_mem1_size", new UnsignedIntegerDataType(),
            "Simulated MEM1 size");
        addAnnotation(memory, 0x8000310C, "g_mem1_arena_start", new UnsignedIntegerDataType(),
            "MEM1 Arena Start (start of usable memory by the game)");
        addAnnotation(memory, 0x80003110, "g_mem1_arena_end", new UnsignedIntegerDataType(),
            "MEM1 Arena End (end of usable memory by the game)");
        addAnnotation(memory, 0x80003118, "g_physical_mem2_size", new UnsignedIntegerDataType(),
            "Physical MEM2 size. (0x3118-0x314C are set by IOS upon reload.)");
        addAnnotation(memory, 0x8000311C, "g_simulated_mem2_size", new UnsignedIntegerDataType(),
            "Simulated MEM2 size");
        addAnnotation(memory, 0x80003120, "g_mem2_end_ppc", new UnsignedIntegerDataType(),
            "End of MEM2 addressable to PPC");
        addAnnotation(memory, 0x80003124, "g_mem2_start_usable", new UnsignedIntegerDataType(),
            "Usable MEM2 Start (start of usable memory by the game)");
        addAnnotation(memory, 0x80003128, "g_mem2_end_usable", new UnsignedIntegerDataType(),
            "Usable MEM2 End (end of usable memory by the game)");
        addAnnotation(memory, 0x80003130, "g_ios_ipc_buffer_start", new UnsignedIntegerDataType(),
            "IOS IPC Buffer Start");
        addAnnotation(memory, 0x80003134, "g_ios_ipc_buffer_end", new UnsignedIntegerDataType(),
            "IOS IPC Buffer End");
        addAnnotation(memory, 0x80003138, "g_hollywood_version", new UnsignedIntegerDataType(),
            "Hollywood Version");
        addAnnotation(memory, 0x80003140, "g_ios_version", new UnsignedIntegerDataType(),
            "IOS version (090204 = IOS9, v2.4)");
        addAnnotation(memory, 0x80003144, "g_ios_build_date", new UnsignedIntegerDataType(),
            "IOS Build Date (62507 = 06/25/07 = June 25, 2007)");
        addAnnotation(memory, 0x80003148, "g_ios_reserved_heap_start",
            new UnsignedIntegerDataType(), "IOS Reserved Heap Start");
        addAnnotation(memory, 0x8000314C, "g_ios_reserved_heap_end", new UnsignedIntegerDataType(),
            "IOS Reserved Heap End");
        addAnnotation(memory, 0x80003158, "g_gddr_vendor_code", new UnsignedIntegerDataType(),
            "GDDR Vendor Code");
        addAnnotation(memory, 0x8000315C, "g_boot_program_flag", new ByteDataType(),
            "During the boot process, u32 0x315c is first set to 0xdeadbeef by IOS in the boot_ppc syscall. The value is set to 0x80 by the NAND Boot Program to indicate that it was loaded by the boot program (and probably 0x81 by apploaders)");
        addAnnotation(memory, 0x8000315D, "g_enable_legacy_di_mode", new ByteDataType(),
            "\"Enable legacy DI\" mode? 0x81 = false, anything else means true (though typically set to 0x80). Required to be set when loading Gamecube apploader.");
        addAnnotation(memory, 0x8000315E, "g_devkit_boot_program_version",
            new UnsignedShortDataType(),
            "\"Devkit boot program version\", written to by the system menu. The value carries over to disc games. 0x0113 appears to mean v1.13.");
        addAnnotation(memory, 0x80003160, "g_init_semaphore", new UnsignedIntegerDataType(),
            "Init semaphore (1-2 main() waits for this to clear)");
        addAnnotation(memory, 0x80003164, "g_gc_mios_mode_flag", new UnsignedIntegerDataType(),
            "GC (MIOS) mode flag, set to 1 by boot2 when MIOS triggers a shutdown; the System Menu reads this and turns off the console if it is set to 1 and state.dat is set appropriately.");
        addAnnotation(memory, 0x80003180, "g_game_id", new UnsignedIntegerDataType(),
            "Game ID 'RSPE' Wii Sports ID. If these 4 bytes don't match the ID at 80000000, WC24 mode in games is disabled.");
        addAnnotation(memory, 0x80003184, "g_application_type", new ByteDataType(),
            "Application type. 0x80 for disc games, 0x81 for channels.");
        addAnnotation(memory, 0x80003186, "g_application_type_2", new ByteDataType(),
            "Application type 2. Appears to be set to the when a game loads a channel (e.g. Mario Kart Wii loading the region select menu will result in this being 0x80 from the disc and the main application type being 0x81, or the Wii Fit channel transitioning to the Wii Fit disc will result in this being 0x81 and the main type being 0x80).");
        addAnnotation(memory, 0x80003188, "g_minimum_ios_version", new UnsignedIntegerDataType(),
            "Minimum IOS version (2 bytes for the major version, 2 bytes for the title version)");
        addAnnotation(memory, 0x8000318C, "g_title_booted_from_nand_launch_code",
            new UnsignedIntegerDataType(), "Title Booted from NAND (Launch Code)");
        addAnnotation(memory, 0x80003190, "g_title_booted_from_nand_return_code",
            new UnsignedIntegerDataType(), "Title Booted from NAND (Return Code)");
        addAnnotation(memory, 0x80003194, "g_partition_type", new UnsignedIntegerDataType(),
            "While reading a disc, the system menu reads the first partition table (0x20 bytes from 0x00040020) and stores a pointer to the data partition entry. When launching the disc game, it copies the partition type to 0x3194. The partition type for data partitions is 0, so typically this location always has 0.");
        addAnnotation(memory, 0x80003198, "g_data_partition_offset", new UnsignedIntegerDataType(),
            "While reading a disc, the system menu reads the first partition table (0x20 bytes from 0x00040020) and stores a pointer to the data partition entry. When launching the disc game, it copies the partition offset to 0x3198.");
        addAnnotation(memory, 0x8000319C, "g_disc_layer_flag", new ByteDataType(),
            "Set by the apploader to 0x80 for single-layer discs and 0x81 for dual-layer discs (determined by whether 0x7ed40000 is the value at offset 0x30 in the partition's bi2.bin; it seems that that value is 0 for single-layer discs). Early titles' apploaders do not set it at all, leaving the value as 0. This controls the out-of-bounds Error #001 read for titles that do make such a read: they try to read at 0x7ed40000 for dual-layer discs and 0x460a0000 for single-layer discs.");
    }

    private void addAnnotation(Memory memory, long address, String name, DataType dataType,
            String comment) throws Exception {
        Address addr = toAddr(address);
        MemoryBlock block = memory.getBlock(addr);
        if (block != null) {
            clearListing(addr, addr.add(dataType.getLength()));
            createLabel(addr, name, true, SourceType.USER_DEFINED);
            createData(addr, dataType);
            setPlateComment(addr, comment);
        }
        else {
            println("Memory block not found at address: " + Long.toHexString(address));
        }
    }
}
