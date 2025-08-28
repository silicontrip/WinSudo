using System;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using static net.ninebroadcast.engineering.sudo.Logger;

namespace net.ninebroadcast.engineering.sudo
{
    /// <summary>
    /// Represents a spawned process and its associated anonymous pipe I/O streams.
    /// This class is responsible for managing the lifecycle of the child process and its I/O forwarding.
    /// </summary>
    public class SudoProcess : IDisposable
    {
        public System.Diagnostics.Process Process { get; private set; }
        public string StdinPipeName { get; internal set; }
        public string StdoutPipeName { get; internal set; }
        public string StderrPipeName { get; internal set; }

        // Internal references to the NamedPipeServerStream objects (for client communication)
        internal NamedPipeServerStream _stdinPipeServer;
        internal NamedPipeServerStream _stdoutPipeServer;
        internal NamedPipeServerStream _stderrPipeServer;

        // Internal references to the anonymous pipe streams (connected to the child process)
        internal Stream _childStdinStream;
        internal Stream _childStdoutStream;
        internal Stream _childStderrStream;

        // Tasks for I/O forwarding
        private Task _stdinForwardingTask;
        private Task _stdoutForwardingTask;
        private Task _stderrForwardingTask;

        public SudoProcess(
            System.Diagnostics.Process process,
            string stdinPipeName,
            string stdoutPipeName,
            string stderrPipeName,
            NamedPipeServerStream stdinPipeServer,
            NamedPipeServerStream stdoutPipeServer,
            NamedPipeServerStream stderrPipeServer,
            Stream childStdinStream,
            Stream childStdoutStream,
            Stream childStderrStream)
        {
            Process = process;
            StdinPipeName = stdinPipeName;
            StdoutPipeName = stdoutPipeName;
            StderrPipeName = stderrPipeName;

            _stdinPipeServer = stdinPipeServer;
            _stdoutPipeServer = stdoutPipeServer;
            _stderrPipeServer = stderrPipeServer;

            _childStdinStream = childStdinStream;
            _childStdoutStream = childStdoutStream;
            _childStderrStream = childStderrStream;

            // Monitor the helper process exit
            Process.EnableRaisingEvents = true;
            Process.Exited += (sender, args) => Dispose(); // Dispose when helper exits
        }

        /// <summary>
        /// Starts the asynchronous I/O forwarding and waits for client connections.
        /// This method should be called once after the SudoProcess object is created.
        /// </summary>
        public async Task RunAsync()
        {
            try
            {
                // Wait for the client to connect to the named pipes.
                await Task.WhenAll(
                    _stdinPipeServer.WaitForConnectionAsync(),
                    _stdoutPipeServer.WaitForConnectionAsync(),
                    _stderrPipeServer.WaitForConnectionAsync()
                );

                // Start I/O forwarding tasks here, now that pipes are connected.
                _stdinForwardingTask = Task.Run(async () => {
                    try
                    {
                        await _stdinPipeServer.CopyToAsync(_childStdinStream);
                    }
                    catch (Exception ex)
                    {
                        Log($"ERROR: Stdin forwarding failed: {ex.Message}");
                    }
                });
                _stdoutForwardingTask = Task.Run(async () => {
                    try
                    {
                        await _childStdoutStream.CopyToAsync(_stdoutPipeServer);
                    }
                    catch (Exception ex)
                    {
                        Log($"ERROR: Stdout forwarding failed: {ex.Message}");
                    }
                });
                _stderrForwardingTask = Task.Run(async () => {
                    try
                    {
                        await _childStderrStream.CopyToAsync(_stderrPipeServer);
                    }
                    catch (Exception ex)
                    {
                        Log($"ERROR: Stderr forwarding failed: {ex.Message}");
                    }
                });

                // The I/O forwarding tasks will run until the streams close.
                // We don't need to wait for Process.WaitForExit() here, as that would prematurely close the pipes.
                // The SudoRequestWorker will wait for the process to exit.
            }
            catch (Exception ex)
            {
                Log($"ERROR in SudoProcess.RunAsync: {ex.Message}");
                // Ensure resources are cleaned up if connection fails
                Dispose();
            }
            // No finally block with Dispose() here, as Dispose() is called when Process.Exited event fires
            // or when SudoRequestWorker disposes the SudoProcess.
        }

        public void Dispose()
        {
            // Dispose of the process object
            Process?.Dispose();

            // Dispose of the pipe servers
            _stdinPipeServer?.Dispose();
            _stdoutPipeServer?.Dispose();
            _stderrPipeServer?.Dispose();

            // Dispose of the child process streams
            _childStdinStream?.Dispose();
            _childStdoutStream?.Dispose();
            _childStderrStream?.Dispose();
        }
    }
}