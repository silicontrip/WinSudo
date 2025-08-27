using System;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.ComponentModel;
using System.Threading.Tasks; // Added for Task.Delay

const string CommandPipeName = "net.nine-broadcast.sudo.cmd"; // Defined as local const

Console.WriteLine($"Attempting to connect to pipe: {CommandPipeName}");

try
{
    using (var pipeClient = new NamedPipeClientStream(".", CommandPipeName, PipeDirection.InOut, PipeOptions.None))
    {
        Console.WriteLine("Connecting to pipe...");
        pipeClient.Connect(5000); // 5-second timeout
        Console.WriteLine("Successfully connected to pipe.");
    }
}
catch (TimeoutException)
{
    Console.Error.WriteLine($"Error: Connection to pipe '{CommandPipeName}' timed out.");
}
catch (Win32Exception win32Ex)
{
    Console.Error.WriteLine($"Win32 Error connecting to pipe: {win32Ex.Message} (ErrorCode: {win32Ex.ErrorCode}, NativeErrorCode: {win32Ex.NativeErrorCode})");
}
catch (Exception ex)
{
    Console.Error.WriteLine($"General Error connecting to pipe: {ex.Message}");
    if (ex.InnerException != null)
    {
        Console.Error.WriteLine($"  Inner Exception: {ex.InnerException.Message}");
    }
}
Console.WriteLine("\nConnection attempt complete.");
