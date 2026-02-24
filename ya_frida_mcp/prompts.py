"""MCP prompt templates for common Frida workflows."""

from fastmcp import FastMCP


def register_prompts(mcp: FastMCP) -> None:
    """Register all MCP prompts."""

    @mcp.prompt
    def frida_hook_function() -> str:
        """Template for hooking a native function with Interceptor."""
        return (
            "To hook a native function, first attach to the target process, "
            "then inject a script like:\n\n"
            "```javascript\n"
            "Interceptor.attach(Module.getExportByName(null, 'open'), {\n"
            "  onEnter(args) {\n"
            "    console.log('open(' + args[0].readUtf8String() + ')');\n"
            "  },\n"
            "  onLeave(retval) {\n"
            "    console.log('=> ' + retval);\n"
            "  }\n"
            "});\n"
            "```\n\n"
            "Steps: frida_attach -> frida_inject -> frida_get_messages"
        )

    @mcp.prompt
    def frida_trace_calls() -> str:
        """Template for tracing function calls with Stalker."""
        return (
            "To trace calls using Stalker:\n\n"
            "```javascript\n"
            "const tid = Process.getCurrentThreadId();\n"
            "Stalker.follow(tid, {\n"
            "  events: { call: true, ret: false },\n"
            "  onCallSummary(summary) {\n"
            "    for (const [addr, count] of Object.entries(summary)) {\n"
            "      const sym = DebugSymbol.fromAddress(ptr(addr));\n"
            "      send({ address: addr, name: sym.name, count });\n"
            "    }\n"
            "  }\n"
            "});\n"
            "```\n\n"
            "Steps: frida_attach -> frida_inject -> frida_get_messages"
        )

    @mcp.prompt
    def frida_hook_java() -> str:
        """Template for hooking Java methods on Android."""
        return (
            "To hook a Java method on Android:\n\n"
            "```javascript\n"
            "Java.perform(() => {\n"
            "  const Activity = Java.use('android.app.Activity');\n"
            "  Activity.onCreate.implementation = function(bundle) {\n"
            "    console.log('onCreate called');\n"
            "    this.onCreate(bundle);\n"
            "  };\n"
            "});\n"
            "```\n\n"
            "Steps: frida_attach (USB device) -> frida_inject -> frida_get_messages"
        )

    @mcp.prompt
    def frida_hook_objc() -> str:
        """Template for hooking Objective-C methods on iOS."""
        return (
            "To hook an ObjC method on iOS:\n\n"
            "```javascript\n"
            "const resolver = new ApiResolver('objc');\n"
            "const matches = resolver.enumerateMatches('-[NSURLSession dataTaskWithRequest:*]');\n"
            "matches.forEach(m => {\n"
            "  Interceptor.attach(m.address, {\n"
            "    onEnter(args) {\n"
            "      const req = new ObjC.Object(args[2]);\n"
            "      send({ url: req.URL().absoluteString().toString() });\n"
            "    }\n"
            "  });\n"
            "});\n"
            "```\n\n"
            "Steps: frida_attach (USB device) -> frida_inject -> frida_get_messages"
        )

    @mcp.prompt
    def frida_android_usb_setup() -> str:
        """Workflow: set up frida-server on an Android device connected via USB."""
        return (
            "When connecting to an Android device via USB (-U) for Frida instrumentation:\n\n"
            "1. Call `frida_server_status` to check if frida-server is running "
            "and whether its version matches the local Frida client.\n"
            "2. If frida-server is not present or the version is mismatched, "
            "call `frida_server_install` to download the correct version, "
            "push it to the device, and start it.\n"
            "3. If frida-server is present but stopped, call `frida_server_start`.\n"
            "4. Once frida-server is confirmed running and version-matched, "
            "proceed with `frida_attach` or `frida_spawn` as needed."
        )

    @mcp.prompt
    def frida_enumerate_and_dump() -> str:
        """Workflow: enumerate modules then dump exports."""
        return (
            "To explore a process's loaded libraries:\n\n"
            "1. Use `frida_ps` to find the target PID\n"
            "2. Use `frida_attach` to create a session\n"
            "3. Use `frida_enumerate_modules` to list loaded modules\n"
            "4. Use `frida_enumerate_exports` on interesting modules\n"
            "5. Use `frida_inject` with Interceptor to hook specific exports"
        )
