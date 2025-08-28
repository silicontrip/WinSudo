using System;
using System.ServiceProcess;
using System.Threading;
using System.Threading.Tasks;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Runtime.InteropServices;

namespace net.ninebroadcast.engineering.sudo
{
    public class SudoService : ServiceBase
    {
        private const string CommandPipeName = "Global\\net.nine-broadcast.sudo.cmd";
        private Thread? _listenerThread;
        private CancellationTokenSource? _cancellationTokenSource;
        private NamedPipeServerStream? _currentPipeServer; // New field to hold the current pipe server

        public SudoService()
        {
            this.ServiceName = "Sudo for Windows Service";
        }

        protected override void OnStart(string[] args)
        {
            _cancellationTokenSource = new CancellationTokenSource();
            _listenerThread = new Thread(ListenForClients);
            _listenerThread.IsBackground = true;
            _listenerThread.Start();
        }

        protected override void OnStop()
        {
            _cancellationTokenSource?.Cancel();
            // Gracefully close the current pipe server to unblock WaitForConnection()
            _currentPipeServer?.Close(); // Close the pipe to unblock the listener thread
            _currentPipeServer?.Dispose(); // Explicitly dispose the pipe server
        }

        private void ListenForClients()
        {
            // Constants for CreateNamedPipe
            const uint PIPE_ACCESS_DUPLEX = 0x00000003;
            const uint FILE_FLAG_OVERLAPPED = 0x40000000;
            const uint PIPE_TYPE_BYTE = 0x00000000;
            const uint PIPE_READMODE_BYTE = 0x00000000;
            const uint PIPE_WAIT = 0x00000000;
            const uint PIPE_UNLIMITED_INSTANCES = 255; // NamedPipeServerStream.MaxAllowedServerInstances is 255

            var cancellationToken = _cancellationTokenSource!.Token;
            while (!cancellationToken.IsCancellationRequested)
            {
                NamedPipeServerStream? pipeServer = null;
                IntPtr hPipe = IntPtr.Zero; // Handle for the named pipe
                IntPtr pSecurityAttributes = IntPtr.Zero; // Pointer to SECURITY_ATTRIBUTES
                IntPtr pSecurityDescriptor = IntPtr.Zero; // Pointer to SECURITY_DESCRIPTOR

                try
                {
                    // dwOpenMode: PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED
                    uint dwOpenMode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED;
                    // dwPipeMode: PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT
                    uint dwPipeMode = PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT;

                    // Define the Security Descriptor Definition Language (SDDL) string.
                    // D:(A;;GA;;;WD) - DACL: Allow Generic All (GA) access to Everyone (WD).
                    // S:(ML;;NW;;;ME) - SACL: Mandatory Label (ML), No Write Up (NW), Medium Integrity Level (ME).
                    // This allows processes at Medium integrity level to write to the pipe.
                    string sddl = $"D:(A;;GA;;;WD)S:(ML;;NW;;;{NativeMethods.SECURITY_MANDATORY_MEDIUM_RID})";

                    uint securityDescriptorSize;
                    if (!NativeMethods.ConvertStringSecurityDescriptorToSecurityDescriptor(
                        sddl,
                        NativeMethods.SDDL_REVISION_1,
                        out pSecurityDescriptor,
                        out securityDescriptorSize))
                    {
                        throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "Failed to convert SDDL to Security Descriptor.");
                    }

                    NativeMethods.SECURITY_ATTRIBUTES sa = new NativeMethods.SECURITY_ATTRIBUTES();
                    sa.nLength = Marshal.SizeOf(sa);
                    sa.lpSecurityDescriptor = pSecurityDescriptor;
                    sa.bInheritHandle = false; // Pipe handle should not be inheritable by child processes

                    pSecurityAttributes = Marshal.AllocHGlobal(Marshal.SizeOf(sa));
                    Marshal.StructureToPtr(sa, pSecurityAttributes, false);

                    hPipe = NativeMethods.CreateNamedPipe(
                        "\\\\.\\pipe\\" + CommandPipeName, // Full pipe name
                        dwOpenMode,
                        dwPipeMode,
                        PIPE_UNLIMITED_INSTANCES,
                        0, // nOutBufferSize
                        0, // nInBufferSize
                        0, // nDefaultTimeOut (use default)
                        pSecurityAttributes // lpSecurityAttributes (now using custom security)
                    );

                    if (hPipe == NativeMethods.INVALID_HANDLE_VALUE)
                    {
                        throw new System.ComponentModel.Win32Exception();
                    }

                    // 2. Wrap the handle in NamedPipeServerStream
                    pipeServer = new NamedPipeServerStream(
                        PipeDirection.InOut,
                        false, // isConnected
                        true, // isAsync
                        new Microsoft.Win32.SafeHandles.SafePipeHandle(hPipe, true) // handle
                    );
                    Console.WriteLine($"NamedPipeServerStream created for '{CommandPipeName}'.");
                    _currentPipeServer = pipeServer;
                    Console.WriteLine($"Waiting for client connection on '{CommandPipeName}'...");
                    pipeServer.WaitForConnection();
                    Console.WriteLine($"Client connected to '{CommandPipeName}'.");

                    // Hand off the connected client to a worker task.
                    var worker = new SudoRequestWorker(pipeServer);
                    Task.Run(() => worker.HandleRequestAsync(), cancellationToken);

                    // Set _currentPipeServer to null only after the pipe has been handed off
                    // and before the loop prepares for the next connection.
                    _currentPipeServer = null;
                }
                catch (Exception ex)
                {
                    // Log the exception from pipe creation or connection
                    Console.Error.WriteLine($"ERROR during pipe creation or connection: {ex.Message}");
                    if (ex is System.ComponentModel.Win32Exception win32Ex)
                    {
                        Console.Error.WriteLine($"  Win32 Error: {win32Ex.Message} (ErrorCode: {win32Ex.ErrorCode}, NativeErrorCode: {win32Ex.NativeErrorCode})");
                    }
                    else if (ex is IOException ioEx)
                    {
                        if (ioEx.InnerException is System.ComponentModel.Win32Exception innerWin32Ex)
                        {
                            Console.Error.WriteLine($"  Inner Win32 Error: {innerWin32Ex.Message} (ErrorCode: {innerWin32Ex.ErrorCode}, NativeErrorCode: {innerWin32Ex.NativeErrorCode})");
                        }
                        else if (ioEx.HResult != 0)
                        {
                            int nativeErrorCode = ioEx.HResult & 0x0000FFFF;
                            Console.Error.WriteLine($"  HResult indicates Win32 Error: {nativeErrorCode}");
                        }
                    }

                    // When pipeServer.Close() is called from OnStop, it will throw an exception here.
                    // We should ignore this specific exception if cancellation is requested.
                    if (cancellationToken.IsCancellationRequested && ex is IOException)
                    {
                        // Expected exception during shutdown, ignore.
                    }
                    else
                    {
                        Console.Error.WriteLine($"ERROR in listener loop: {ex.Message}");
                        // Add a small delay to prevent tight looping on persistent errors
                        Thread.Sleep(1000);
                    }
                    // Ensure pipe is disposed if creation failed or connection failed before handing off
                    pipeServer?.Dispose();
                }
                finally
                {
                    // hPipe is owned by SafePipeHandle, which is owned by pipeServer.
                    // pipeServer is disposed by SudoRequestWorker, or when it goes out of scope.
                    // So, no need to call CloseHandle(hPipe) here.
                    if (pSecurityAttributes != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(pSecurityAttributes);
                    }
                    if (pSecurityDescriptor != IntPtr.Zero)
                    {
                        NativeMethods.LocalFree(pSecurityDescriptor);
                    }
                }
            }
        }

        // This allows running the service as a console app for easy debugging.
        public void RunAsConsole(string[] args)
        {
            OnStart(args);
            Console.WriteLine("Service is running in console mode. Press Enter to stop.");
            Console.ReadLine();
            OnStop();
        }

        /// <summary>
        /// Helper method to convert PipeSecurity to a marshaled SECURITY_ATTRIBUTES pointer.
        /// The caller is responsible for freeing the returned IntPtr using Marshal.FreeHGlobal.
        /// </summary>
        /// <param name="pipeSecurity">The PipeSecurity object.</param>
        /// <returns>An IntPtr to the marshaled SECURITY_ATTRIBUTES structure, or IntPtr.Zero if pipeSecurity is null.</returns>
        private IntPtr GetSecurityAttributesForPipeSecurity(PipeSecurity pipeSecurity)
        {
            if (pipeSecurity == null)
            {
                return IntPtr.Zero;
            }

            // Get the raw security descriptor from the PipeSecurity object
            byte[] sdBytes = pipeSecurity.GetSecurityDescriptorBinaryForm();

            // Allocate unmanaged memory for the SECURITY_DESCRIPTOR
            IntPtr pSecurityDescriptor = Marshal.AllocHGlobal(sdBytes.Length);
            Marshal.Copy(sdBytes, 0, pSecurityDescriptor, sdBytes.Length);

            // Allocate unmanaged memory for the SECURITY_ATTRIBUTES structure
            NativeMethods.SECURITY_ATTRIBUTES sa = new NativeMethods.SECURITY_ATTRIBUTES();
            sa.nLength = Marshal.SizeOf(sa);
            sa.lpSecurityDescriptor = pSecurityDescriptor;
            sa.bInheritHandle = false; // We don't want the pipe handle to be inheritable by default

            IntPtr pSecurityAttributes = Marshal.AllocHGlobal(Marshal.SizeOf(sa));
            Marshal.StructureToPtr(sa, pSecurityAttributes, false);

            // The caller is responsible for freeing both pSecurityDescriptor and pSecurityAttributes
            // in the finally block of the calling method.
            return pSecurityAttributes;
        }
    }
}