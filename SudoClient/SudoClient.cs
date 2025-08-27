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
                Console.WriteLine($"Attempting to connect to named pipe '{CommandPipeName}'...");
                using (var commandPipe = new NamedPipeClientStream(".", CommandPipeName, PipeDirection.InOut, PipeOptions.None))
                {
                    await commandPipe.ConnectAsync(5000);
                    Console.WriteLine("Successfully connected to named pipe.");

                    var jsonOptions = new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

                    await JsonSerializer.SerializeAsync(commandPipe, request, jsonOptions);

                    var response = await JsonSerializer.DeserializeAsync<SudoServerResponse>(commandPipe, jsonOptions);
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
                        await JsonSerializer.SerializeAsync(commandPipe, authRequest, jsonOptions);

                        response = await JsonSerializer.DeserializeAsync<SudoServerResponse>(commandPipe, jsonOptions);
                        if (response == null)
                        {
                            Console.Error.WriteLine("Error: Received empty or invalid response from server after authentication attempt.");
                            return;
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
            try
            {
                using (var stdinPipe = new NamedPipeClientStream(".", successData.StdinPipeName!, PipeDirection.Out, PipeOptions.None))
                using (var stdoutPipe = new NamedPipeClientStream(".", successData.StdoutPipeName!, PipeDirection.In, PipeOptions.None))
                using (var stderrPipe = new NamedPipeClientStream(".", successData.StderrPipeName!, PipeDirection.In, PipeOptions.None))
                {
                    await Task.WhenAll(
                        stdinPipe.ConnectAsync(5000),
                        stdoutPipe.ConnectAsync(5000),
                        stderrPipe.ConnectAsync(5000)
                    );

                    var stdinTask = Console.OpenStandardInput().CopyToAsync(stdinPipe);
                    var stdoutTask = stdoutPipe.CopyToAsync(Console.OpenStandardOutput());
                    var stderrTask = stderrPipe.CopyToAsync(Console.OpenStandardError());

                    await Task.WhenAll(stdinTask, stdoutTask, stderrTask);
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"I/O Error: {ex.Message}");
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
                            // TODO: Implement session parsing
                            if (i + 1 < args.Length)
                            {
                                // request.SessionDescriptor = args[++i];
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