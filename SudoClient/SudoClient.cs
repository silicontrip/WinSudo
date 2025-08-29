using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace net.ninebroadcast.engineering.sudo
{
    public class SudoClient
    {
        private const string CommandPipeName = "Global\\net.nine-broadcast.sudo.cmd";

        public static async Task Main(string[] args)
        {
            if (args.Length == 0)
            {
                ShowUsage();
                return;
            }

            var request = ParseArguments(args);
            if (request == null)
            {
                ShowUsage();
                return;
            }

            try
            {
                //Console.WriteLine($"Attempting to connect to named pipe '{CommandPipeName}'...");
                using (var commandPipe = new NamedPipeClientStream(".", CommandPipeName, PipeDirection.InOut, PipeOptions.None))
                {
                    await commandPipe.ConnectAsync(5000);
                    //Console.WriteLine("Successfully connected to named pipe.");

                    var jsonOptions = new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

                    //Console.WriteLine("Client: Attempting to serialize request to pipe...");
                    await WriteMessageAsync(commandPipe, request, jsonOptions);
                    //Console.WriteLine("Client: Request serialized. Attempting to deserialize response from pipe...");

                    var response = await ReadMessageAsync<SudoServerResponse>(commandPipe, jsonOptions);
                    //Console.WriteLine("Client: Response deserialized from pipe.");
                    if (response == null)
                    {
                        Console.Error.WriteLine("Error: Received empty or invalid response from server.");
                        return;
                    }

                    if (response.Status == "authentication_required")
                    {
                        Console.Write("Password: ");
                        string password = ReadPassword();

                        var authRequest = new SudoRequest { Password = password };
                        //Console.WriteLine("Client: Attempting to serialize authentication request to pipe...");
                        await WriteMessageAsync(commandPipe, authRequest, jsonOptions);
                        //Console.WriteLine("Client: Authentication request serialized. Attempting to deserialize response from pipe...");

                        response = await ReadMessageAsync<SudoServerResponse>(commandPipe, jsonOptions);
                        //Console.WriteLine("Client: Authentication response deserialized from pipe.");
                        if (response == null)
                        {
                            Console.Error.WriteLine("Error: Received empty or invalid response from server after authentication attempt.");
                            return;
                        }
                        Console.WriteLine($"Client: Response status after authentication: {response.Status}");
                        if (response.Status != "success_proceed_to_io")
                        {
                            Console.Error.WriteLine($"Client: Error message after authentication: {response.ErrorMessage}");
                        }
                    }

                    if (response.Status == "success_proceed_to_io")
                    {
                        await HandleIoForwarding(response);
                    }
                    else
                    {
                        Console.Error.WriteLine($"Error: {response.ErrorMessage}");
                    }
                }
            }
            catch (System.ComponentModel.Win32Exception win32Ex)
            {
                Console.Error.WriteLine($"Win32 Error: {win32Ex.Message} (ErrorCode: {win32Ex.ErrorCode}, NativeErrorCode: {win32Ex.NativeErrorCode})");
            }
            catch (IOException ioEx)
            {
                Console.Error.WriteLine($"I/O Error: {ioEx.Message}");
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
            catch (Exception ex)
            {
                Console.Error.WriteLine($"General Error: {ex.Message}");
                Console.Error.WriteLine($"Exception Type: {ex.GetType().FullName}");
                if (ex.InnerException != null)
                {
                    Console.Error.WriteLine($"Inner Exception Type: {ex.InnerException.GetType().FullName}");
                    Console.Error.WriteLine($"Inner Exception Message: {ex.InnerException.Message}");
                }
            }
        }

        private static async Task HandleIoForwarding(SudoServerResponse successData)
        {
            //Console.WriteLine("Client: Entering HandleIoForwarding.");
            NamedPipeClientStream stdinPipe = null; // Declare outside try-block for finally access
            try
            {
                stdinPipe = new NamedPipeClientStream(".", successData.StdinPipeName!, PipeDirection.Out, PipeOptions.None);
                using (var stdoutPipe = new NamedPipeClientStream(".", successData.StdoutPipeName!, PipeDirection.In, PipeOptions.None))
                using (var stderrPipe = new NamedPipeClientStream(".", successData.StderrPipeName!, PipeDirection.In, PipeOptions.None))
                {
                    await Task.WhenAll(
                        stdinPipe.ConnectAsync(5000),
                        stdoutPipe.ConnectAsync(5000),
                        stderrPipe.ConnectAsync(5000)
                    );

                    // Use a CancellationTokenSource for stdin, but also prepare to close the pipe
                    var stdinCancellationTokenSource = new CancellationTokenSource();
                    var stdinTask = Console.OpenStandardInput().CopyToAsync(stdinPipe, stdinCancellationTokenSource.Token);

                    var stdoutTask = stdoutPipe.CopyToAsync(Console.OpenStandardOutput());
                    var stderrTask = stderrPipe.CopyToAsync(Console.OpenStandardError());

                    // Wait for either stdout or stderr to complete
                    var outputCompletionTask = Task.WhenAny(stdoutTask, stderrTask);
                    await outputCompletionTask;

                    // Output stream completed. Stop forwarding stdin.
                    // Explicitly close the stdinPipe to unblock CopyToAsync if it's waiting to write.
                    // This will cause stdinTask to complete (likely with an IOException).
                    stdinPipe.Dispose(); // This will close the pipe and unblock CopyToAsync

                    // Now wait for all tasks to complete. stdinTask should now complete.
                    try
                    {
                        await Task.WhenAll(stdinTask, stdoutTask, stderrTask);
                    }
                    catch (OperationCanceledException)
                    {
                        Console.WriteLine("Client: stdin forwarding cancelled.");
                    }
                    catch (IOException ioEx)
                    {
                        // Expected if stdinPipe was disposed while CopyToAsync was active
                        Console.WriteLine($"Client: stdin pipe closed: {ioEx.Message}");
                    }
                    catch (Exception ex)
                    {
                        Console.Error.WriteLine($"Client: Error waiting for I/O tasks: {ex.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Client I/O Error in HandleIoForwarding: {ex.Message}");
            }
            finally
            {
                // Ensure stdinPipe is disposed even if an exception occurs earlier
                stdinPipe?.Dispose();
            }
        }

        private static SudoRequest? ParseArguments(string[] args)
        {
            var request = new SudoRequest();
            var commandArgs = new List<string>();
            
            request.Mode = "sudo"; // Default mode

            for (int i = 0; i < args.Length; i++)
            {
                string arg = args[i];
                if (arg.StartsWith("/"))
                {
                    switch (arg.ToLower())
                    {
                        case "/u":
                            if (i + 1 < args.Length)
                            {
                                request.Mode = "su";
                                request.TargetUser = args[++i];
                            }
                            else
                            {
                                return null; // Invalid usage
                            }
                            break;
                        case "/s":
                            if (i + 1 < args.Length)
                            {
                                if (uint.TryParse(args[++i], out uint sessionId))
                                {
                                    request.SessionId = sessionId;
                                }
                                else
                                {
                                    Console.Error.WriteLine($"Invalid session ID format: {args[i]}. Must be a positive integer.");
                                    return null; // Invalid usage
                                }
                            }
                            else
                            {
                                return null; // Invalid usage
                            }
                            break;
                        default:
                            return null; // Invalid flag
                    }
                }
                else
                {
                    commandArgs.Add(arg);
                }
            }

            if (commandArgs.Count == 0)
            {
                return null; // No command specified
            }

            request.Command = string.Join(" ", commandArgs);
            return request;
        }

        private static async Task WriteMessageAsync<T>(Stream stream, T message, JsonSerializerOptions options)
        {
            Console.WriteLine($"Client: WriteMessageAsync: Attempting to serialize message of type {typeof(T).Name}.");
            using (var ms = new MemoryStream())
            {
                await JsonSerializer.SerializeAsync(ms, message, options);
                var bytes = ms.ToArray();

                using (var bw = new BinaryWriter(stream, Encoding.UTF8, leaveOpen: true))
                {
                    bw.Write(bytes.Length); // Writes the 4-byte length prefix
                    bw.Write(bytes);        // Writes the actual message payload
                    bw.Flush();             // Ensure all buffered data is written to the underlying stream
                }
                Console.WriteLine($"Client: WriteMessageAsync: Wrote {bytes.Length} bytes (plus 4 for length). Message type: {typeof(T).Name}.");
            }
        }

        private static async Task<T?> ReadMessageAsync<T>(Stream stream, JsonSerializerOptions options)
        {
            Console.WriteLine($"Client: ReadMessageAsync: Attempting to read message of type {typeof(T).Name}.");
            int length;
            byte[] messageBytes;

            using (var br = new BinaryReader(stream, Encoding.UTF8, leaveOpen: true))
            {
                try
                {
                    length = br.ReadInt32(); // Reads 4 bytes as int (little-endian by default)
                    Console.WriteLine($"Client: ReadMessageAsync: Read message length: {length} bytes.");
                }
                catch (EndOfStreamException)
                {
                    Console.Error.WriteLine("Client: ReadMessageAsync: End of stream reached while reading length.");
                    return default(T); // Pipe closed prematurely
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"Client: ReadMessageAsync: Error reading length: {ex.Message}");
                    return default(T);
                }

                if (length <= 0) throw new IOException("Invalid message length.");

                try
                {
                    messageBytes = br.ReadBytes(length); // Reads the actual message payload
                    Console.WriteLine($"Client: ReadMessageAsync: Read {messageBytes.Length} bytes for message payload.");
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"Client: ReadMessageAsync: Error reading message payload: {ex.Message}");
                    throw new IOException("Pipe closed prematurely or failed to read full message.", ex);
                }

                if (messageBytes.Length != length)
                {
                    throw new IOException("Pipe closed prematurely or failed to read full message.");
                }
            }

            using (var ms = new MemoryStream(messageBytes))
            {
                Console.WriteLine($"Client: ReadMessageAsync: Deserializing message of type {typeof(T).Name}.");
                return await JsonSerializer.DeserializeAsync<T>(ms, options);
            }
        }

        private static void ShowUsage()
        {
            Console.WriteLine("Usage: sudo.exe [/u <user>] [/s <session>] <command_to_run>");
        }

        private static string ReadPassword()
        {
            var password = new StringBuilder();
            while (true)
            {
                ConsoleKeyInfo key = Console.ReadKey(true);
                if (key.Key == ConsoleKey.Enter) break;
                if (key.Key == ConsoleKey.Backspace && password.Length > 0)
                {
                    password.Remove(password.Length - 1, 1);
                }
                else if (!char.IsControl(key.KeyChar))
                {
                    password.Append(key.KeyChar);
                }
            }
            Console.WriteLine();
            return password.ToString();
        }
    }
}