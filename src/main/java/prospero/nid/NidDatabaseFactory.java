package prospero.nid;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.Map;

import ghidra.framework.Application;

import generic.jar.ResourceFile;

public class NidDatabaseFactory {

	private static final String AEROLIB = "aerolib.csv";

    private NidDatabaseFactory() {
    }

	private static String[] split(String line) {
		// this is more efficient since it doesn't use regex
		int index = line.indexOf(' ');
		if (index == -1) {
			return null;
		}
		return new String[]{line.substring(0, index), line.substring(index + 1)};
	}

    public static Map<String, String> getNidDatabase() throws Exception {
		ResourceFile file = Application.findDataFileInAnyModule(AEROLIB);
		if (file == null) {
			throw new Exception(AEROLIB + " not found! Please check the plugin installation.");
		}

		try (BufferedReader reader = new BufferedReader(new InputStreamReader(file.getInputStream()))) {
			Map<String, String> result = new HashMap<>();
	        while (true) {
				String line = reader.readLine();
				if (line == null || line.isBlank()) {
					return result;
				}
				String[] values = split(line);
				if (values == null) {
					throw new IOException("Malformed "+AEROLIB);
				}
				if (values.length > 2) {
					continue;
				}
	            result.put(values[0], values[1]);
	        }
		}
    }

}
