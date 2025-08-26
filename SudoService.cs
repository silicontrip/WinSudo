
using System;
using System.ServiceProcess;
using System.Threading;
using System.Threading.Tasks;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;

namespace net.ninebroadcast.engineering.sudo
{
    public class SudoService : ServiceBase
    {
        private const string CommandPipeName = "net.nine-broadcast.sudo.cmd";
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
            _listenerThread?.Join();
        }

        private void ListenForClients()
        {
            var cancellationToken = _cancellationTokenSource!.Token;
            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    // Create a new pipe for each client.
                    // A more advanced implementation might use a pool of pipes.
                    // Create PipeSecurity to allow access for non-admin users
                    var ps = new PipeSecurity();
                    // Allow Everyone to read and write to the pipe
                    // For more restrictive scenarios, use WellKnownSidType.BuiltinUsersSid
                    ps.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.WorldSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));

                    // Create a new pipe for each client with the specified security.
                    var pipeServer = new NamedPipeServerStream(
                        CommandPipeName,
                        PipeDirection.InOut,
                        NamedPipeServerStream.MaxAllowedServerInstances,
                        PipeTransmissionMode.Byte,
                        PipeOptions.None,
                        0, // inBufferSize
                        0  // outBufferSize
                    );
                    pipeServer.SetAccessControl(ps); // Apply security after creation
                    _currentPipeServer = pipeServer; // Assign the current pipe server
                    // Wait for a client to connect.
                    // This is a blocking call, cancellation would require a more complex setup.
                    pipeServer.WaitForConnection();
                    _currentPipeServer = null; // Clear the reference after connection

                    // Hand off the connected client to a worker task.
                    var worker = new SudoRequestWorker(pipeServer);
                    Task.Run(() => worker.HandleRequestAsync(), cancellationToken);
                }
                catch (Exception ex)
                {
                    // When pipeServer.Close() is called from OnStop, it will throw an exception here.
                    // We should ignore this specific exception if cancellation is requested.
                    if (cancellationToken.IsCancellationRequested && ex is IOException)
                    {
                        // Expected exception during shutdown, ignore.
                    }
                    else
                    {
                        System.Diagnostics.Debug.WriteLine($"ERROR in listener loop: {ex.Message}");
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
    }
}
