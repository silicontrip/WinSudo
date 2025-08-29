using System;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Diagnostics;
using static net.ninebroadcast.engineering.sudo.Logger;

namespace net.ninebroadcast.engineering.sudo
{
    public class PipeProcessSpawner : ISudoProcessSpawner
    {
        public SudoProcess Spawn(IntPtr userToken, string command, ProcessSpawnerOptions options)
        {
            // Anonymous pipe handles for the child process's standard I/O.
            IntPtr hChildStd_In_Rd = IntPtr.Zero, hChildStd_In_Wr = IntPtr.Zero;
            IntPtr hChildStd_Out_Rd = IntPtr.Zero, hChildStd_Out_Wr = IntPtr.Zero;
            IntPtr hChildStd_Err_Rd = IntPtr.Zero, hChildStd_Err_Wr = IntPtr.Zero;

            // Parent-side handles for the anonymous pipes.
            IntPtr hParentStd_In_Wr = IntPtr.Zero; // Parent writes to child's stdin
            IntPtr hParentStd_Out_Rd = IntPtr.Zero; // Parent reads from child's stdout
            IntPtr hParentStd_Err_Rd = IntPtr.Zero; // Parent reads from child's stderr

            // Named pipe server streams for client communication.
            String pipeBaseName = Guid.NewGuid().ToString();
            string stdinPipeName = "stdin-" + pipeBaseName;
            string stdoutPipeName = "stdout-" + pipeBaseName;
            string stderrPipeName = "stderr-" + pipeBaseName;

            NamedPipeServerStream stdinPipeServer = null!;
            NamedPipeServerStream stdoutPipeServer = null!;
            NamedPipeServerStream stderrPipeServer = null!;

            System.Diagnostics.Process childProcess = null!;

            try
            {
                // 1. Create the anonymous pipes for the child process.
                CreateInheritablePipe(out hParentStd_In_Wr, out hChildStd_In_Rd, PipeDirection.Out); // Parent writes to child's stdin
                CreateInheritablePipe(out hParentStd_Out_Rd, out hChildStd_Out_Wr, PipeDirection.In); // Parent reads from child's stdout
                CreateInheritablePipe(out hParentStd_Err_Rd, out hChildStd_Err_Wr, PipeDirection.In); // Parent reads from child's stderr

                // 2. Prepare STARTUPINFO for the child process.
                var startInfo = new NativeMethods.STARTUPINFO();
                startInfo.cb = Marshal.SizeOf(startInfo);
                startInfo.dwFlags = (uint)NativeMethods.StartupInfoFlags.STARTF_USESTDHANDLES;
                startInfo.hStdInput = hChildStd_In_Rd;
                startInfo.hStdOutput = hChildStd_Out_Wr;
                startInfo.hStdError = hChildStd_Err_Wr;

                // 3. Prepare SECURITY_ATTRIBUTES for CreateProcessAsUser.
                var sa = new NativeMethods.SECURITY_ATTRIBUTES();
                sa.nLength = Marshal.SizeOf(sa);
                sa.bInheritHandle = false; // We are explicitly managing handle inheritance.

                // 4. Launch the child process using CreateProcessAsUser.
                var creationFlags = NativeMethods.CreationFlags.CREATE_UNICODE_ENVIRONMENT | NativeMethods.CreationFlags.CREATE_NO_WINDOW | NativeMethods.CreationFlags.CREATE_SUSPENDED;
                if (!NativeMethods.CreateProcessAsUser(userToken, null, command, ref sa, ref sa, true, creationFlags, IntPtr.Zero, options.WorkingDirectory, ref startInfo, out var processInfo))
                {
                    throw new System.ComponentModel.Win32Exception();
                }

                // Set the session ID for the new process's primary token if specified
                if (options.SessionId.HasValue)
                {
                    uint sessionId = options.SessionId.Value;
                    if (!NativeMethods.SetTokenInformation(processInfo.hProcess, NativeMethods.TOKEN_INFORMATION_CLASS.TokenSessionId, ref sessionId, sizeof(uint)))
                    {
                        // Log or handle error if setting session ID fails
                        System.Diagnostics.Debug.WriteLine($"Failed to set session ID {sessionId} for new process. Error: {Marshal.GetLastWin32Error()}");
                    }
                }

                // Resume the process's primary thread
                NativeMethods.ResumeThread(processInfo.hThread);
                {
                    throw new System.ComponentModel.Win32Exception();
                }

                // 5. Close the child-side anonymous pipe handles in the parent process.
                // These handles are now owned by the child process.
                NativeMethods.CloseHandle(hChildStd_In_Rd);
                NativeMethods.CloseHandle(hChildStd_Out_Wr);
                NativeMethods.CloseHandle(hChildStd_Err_Wr);

                childProcess = System.Diagnostics.Process.GetProcessById((int)processInfo.dwProcessId);

                // 6. Create the three named pipes for the client to connect to.
                stdinPipeServer = CreateNamedPipeServerStreamWithSecurity(stdinPipeName, PipeDirection.In);
                stdoutPipeServer = CreateNamedPipeServerStreamWithSecurity(stdoutPipeName, PipeDirection.Out);
                stderrPipeServer = CreateNamedPipeServerStreamWithSecurity(stderrPipeName, PipeDirection.Out);

                // 7. Return the new process and the parent-side streams for the caller to manage.
                var sudoProcess = new SudoProcess(
                    childProcess,
                    stdinPipeName,
                    stdoutPipeName,
                    stderrPipeName,
                    stdinPipeServer,
                    stdoutPipeServer,
                    stderrPipeServer,
                    new System.IO.FileStream(new Microsoft.Win32.SafeHandles.SafeFileHandle(hParentStd_In_Wr, true), FileAccess.Write, 1, false),
                    new System.IO.FileStream(new Microsoft.Win32.SafeHandles.SafeFileHandle(hParentStd_Out_Rd, true), FileAccess.Read, 1, false),
                    new System.IO.FileStream(new Microsoft.Win32.SafeHandles.SafeFileHandle(hParentStd_Err_Rd, true), FileAccess.Read, 1, false)
                );

                // Start the I/O forwarding tasks in the background.
                _ = sudoProcess.RunAsync();

                return sudoProcess;
            }
            catch (Exception)
            {
                // In case of failure, clean up any handles or pipes that were created.
                if (hChildStd_In_Rd != IntPtr.Zero) NativeMethods.CloseHandle(hChildStd_In_Rd);
                if (hChildStd_In_Wr != IntPtr.Zero) NativeMethods.CloseHandle(hChildStd_In_Wr);
                if (hChildStd_Out_Rd != IntPtr.Zero) NativeMethods.CloseHandle(hChildStd_Out_Rd);
                if (hChildStd_Out_Wr != IntPtr.Zero) NativeMethods.CloseHandle(hChildStd_Out_Wr);
                if (hChildStd_Err_Rd != IntPtr.Zero) NativeMethods.CloseHandle(hChildStd_Err_Rd);
                if (hChildStd_Err_Wr != IntPtr.Zero) NativeMethods.CloseHandle(hChildStd_Err_Wr);

                if (hParentStd_In_Wr != IntPtr.Zero) NativeMethods.CloseHandle(hParentStd_In_Wr);
                if (hParentStd_Out_Rd != IntPtr.Zero) NativeMethods.CloseHandle(hParentStd_Out_Rd);
                if (hParentStd_Err_Rd != IntPtr.Zero) NativeMethods.CloseHandle(hParentStd_Err_Rd);

                stdinPipeServer?.Dispose();
                stdoutPipeServer?.Dispose();
                stderrPipeServer?.Dispose();
                childProcess?.Dispose();
                throw;
            }
        }

        /// <summary>
        /// Creates a pair of anonymous pipe handles, ensuring the child's handle is inheritable
        /// and the parent's handle is not.
        /// </summary>
        /// <param name="hParent">The parent's handle to the pipe (e.g., for reading from child's stdout).</param>
        /// <param name="hChild">The child's handle to the pipe (e.g., for writing to stdout).</param>
        private void CreateInheritablePipe(out IntPtr hParent, out IntPtr hChild, PipeDirection direction)
        {
            IntPtr pSa = IntPtr.Zero; // Declare IntPtr for marshaled SECURITY_ATTRIBUTES
            try
            {
                var sa = new NativeMethods.SECURITY_ATTRIBUTES();
                sa.nLength = Marshal.SizeOf(sa);
                sa.bInheritHandle = true;
                sa.lpSecurityDescriptor = IntPtr.Zero;

                // Marshal the SECURITY_ATTRIBUTES struct to unmanaged memory
                pSa = Marshal.AllocHGlobal(sa.nLength);
                Marshal.StructureToPtr(sa, pSa, false);

                if (!NativeMethods.CreatePipe(out IntPtr hRead, out IntPtr hWrite, pSa, 0))
            {
                throw new System.ComponentModel.Win32Exception();
            }

            IntPtr hChildTemp, hParentTemp;
            if (direction == PipeDirection.In)
            {
                hParentTemp = hRead;
                hChildTemp = hWrite;
            }
            else
            {
                hParentTemp = hWrite;
                hChildTemp = hRead;
            }

            if (!NativeMethods.SetHandleInformation(hParentTemp, (uint)NativeMethods.HANDLE_FLAGS.INHERIT, 0))
            {
                throw new System.ComponentModel.Win32Exception();
            }

            IntPtr hCurrentProcess = System.Diagnostics.Process.GetCurrentProcess().Handle;
            if (!NativeMethods.DuplicateHandle(hCurrentProcess, hChildTemp, hCurrentProcess, out hChild, 0, true, 2 /* DUPLICATE_SAME_ACCESS */))
            {
                throw new System.ComponentModel.Win32Exception();
            }

            NativeMethods.CloseHandle(hChildTemp);
            hParent = hParentTemp;
            }
            finally
            {
                if (pSa != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(pSa); // Free the allocated unmanaged memory
                }
            }
        }

        private NamedPipeServerStream CreateNamedPipeServerStreamWithSecurity(string pipeName, PipeDirection direction)
        {
            // Constants for CreateNamedPipe
            const uint PIPE_ACCESS_DUPLEX = 0x00000003;
            const uint FILE_FLAG_OVERLAPPED = 0x40000000;
            const uint PIPE_TYPE_BYTE = 0x00000000;
            const uint PIPE_READMODE_BYTE = 0x00000000;
            const uint PIPE_WAIT = 0x00000000;
            const uint PIPE_UNLIMITED_INSTANCES = 255;

            IntPtr hPipe = IntPtr.Zero;
            IntPtr pSecurityAttributes = IntPtr.Zero;
            IntPtr pSecurityDescriptor = IntPtr.Zero;

            try
            {
                uint dwOpenMode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED;
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
                sa.bInheritHandle = false;

                pSecurityAttributes = Marshal.AllocHGlobal(Marshal.SizeOf(sa));
                Marshal.StructureToPtr(sa, pSecurityAttributes, false);

                hPipe = NativeMethods.CreateNamedPipe(
                    "\\\\.\\pipe\\" + pipeName,
                    dwOpenMode,
                    dwPipeMode,
                    PIPE_UNLIMITED_INSTANCES,
                    0, // nOutBufferSize
                    0, // nInBufferSize
                    0, // nDefaultTimeOut
                    pSecurityAttributes
                );

                if (hPipe == NativeMethods.INVALID_HANDLE_VALUE)
                {
                    throw new System.ComponentModel.Win32Exception();
                }

                return new NamedPipeServerStream(
                    direction,
                    false, // isConnected
                    true, // isAsync
                    new Microsoft.Win32.SafeHandles.SafePipeHandle(hPipe, true)
                );
            }
            finally
            {
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
}
