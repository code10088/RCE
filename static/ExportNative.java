// Export selected local IL2CPP functions without modifying the APK.
// @category IL2CPP
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import com.google.gson.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;

public class ExportNative extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        Path selection = Paths.get(args[0]);
        Path output = Paths.get(args[1]);
        int timeout = Integer.parseInt(args[2]);
        JsonArray methods = JsonParser.parseString(Files.readString(selection, StandardCharsets.UTF_8)).getAsJsonArray();
        JsonArray index = new JsonArray();
        Path functions = output.resolve("functions");
        Files.createDirectories(functions);
        // Addresses from Il2CppDumper are ELF virtual addresses, not file offsets.
        for (JsonElement element : methods) {
            JsonObject item = element.getAsJsonObject();
            Address address = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(item.get("Address").getAsLong());
            if (!currentProgram.getMemory().contains(address)) continue;
            disassemble(address);
            Function function = getFunctionAt(address);
            if (function == null) function = createFunction(address, null);
            if (function != null) {
                String label = item.get("Name").getAsString().replaceAll("[^A-Za-z0-9_]", "_");
                function.setName(label + "_" + address.toString(), SourceType.USER_DEFINED);
            }
        }
        DecompInterface decompiler = new DecompInterface();
        try {
            if (!decompiler.openProgram(currentProgram)) throw new IllegalStateException(decompiler.getLastMessage());
            for (JsonElement element : methods) {
                monitor.checkCancelled();
                JsonObject item = element.getAsJsonObject();
                JsonObject record = new JsonObject();
                record.addProperty("name", item.get("Name").getAsString());
                long value = item.get("Address").getAsLong();
                record.addProperty("address", "0x" + Long.toHexString(value));
                record.addProperty("metadata_signature", item.get("Signature").getAsString());
                Address address = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(value);
                Function function = getFunctionAt(address);
                if (function == null) {
                    record.addProperty("success", false);
                    record.addProperty("error", "No function created at mapped address");
                } else {
                    DecompileResults result = decompiler.decompileFunction(function, timeout, monitor);
                    boolean success = result.decompileCompleted() && result.getDecompiledFunction() != null;
                    record.addProperty("success", success);
                    if (success) {
                        String filename = "function_" + Long.toHexString(value) + ".c";
                        String text = "/* IL2CPP: " + item.get("Name").getAsString().replace("*/", "* /") +
                            "\nMetadata signature (not applied to inferred ABI): " + item.get("Signature").getAsString().replace("*/", "* /") +
                            "\nPseudo-C; inferred types and locals require review. */\n\n" + result.getDecompiledFunction().getC();
                        Files.writeString(functions.resolve(filename), text, StandardCharsets.UTF_8);
                        record.addProperty("file", "functions/" + filename);
                    } else record.addProperty("error", result.getErrorMessage());
                }
                index.add(record);
                Files.writeString(output.resolve("index.json"), new GsonBuilder().setPrettyPrinting().create().toJson(index), StandardCharsets.UTF_8);
                println(record.get("name").getAsString() + ": " + record.get("success"));
            }
        } finally {
            decompiler.dispose();
        }
    }
}
