"use strict";

function initializeScript() {
    host.diagnostics.debugLog("=== Edge Credential JSON Search Script Loaded ===\n");
    return [];
}

function invokeScript() {
    host.diagnostics.debugLog("=== Starting credential search ===\n");

    try {
        // Search for high-signal JSON fragments (adjust address/range as needed)
        var searchResults = host.namespace.Debugger.State.Sessions[0]
            .Processes[0]
            .Memory.Search("password_value", "a");  // "a" = ASCII

        host.diagnostics.debugLog("Found " + searchResults.Count() + " raw hits for 'password_value'\n");

        // Iterate and dump context for JSON-like structures
        for (var i = 0; i < Math.min(50, searchResults.Count()); i++) {  // Limit to avoid overload
            var addr = searchResults[i].Address;
            host.diagnostics.debugLog("Hit at: " + addr.toString(16) + "\n");
            host.namespace.Debugger.Utility.Control.ExecuteCommand("da " + addr.toString(16) + " L100");
        }

        // Add more patterns as needed
        // host.namespace.Debugger.Utility.Control.ExecuteCommand("s -a 0 L?0x10000000 \"{\\\"origin\\\"\"");

    } catch (e) {
        host.diagnostics.debugLog("Error: " + e + "\n");
    }

    host.diagnostics.debugLog("=== Search complete ===\n");
}
