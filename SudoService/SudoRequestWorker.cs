using System;
using System.IO;
using System.IO.Pipes;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using static net.ninebroadcast.engineering.sudo.Logger;

namespace net.ninebroadcast.engineering.sudo
{
    public class SudoRequestWorker
    {
        private readonly NamedPipeServerStream _commandPipe;
        private readonly JsonSerializerOptions _jsonOptions;
        private readonly ISudoProcessSpawner _processSpawner;

        public SudoRequestWorker(NamedPipeServerStream commandPipe)
        {
            System.Diagnostics.Debug.WriteLine("Server: SudoRequestWorker constructor entered.");
            _commandPipe = commandPipe;
            _jsonOptions = new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true,
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            };
            _processSpawner = new PipeProcessSpawner();
        }

        public async Task HandleRequestAsync()
        {
            IntPtr clientToken = IntPtr.Zero;
            IntPtr userToken = IntPtr.Zero;
            SudoProcess sudoProcess = null!;
 
            try
            {
                Log("SudoRequestWorker: HandleRequestAsync entered.");
                Console.WriteLine("Server: HandleRequestAsync started.");
                Console.WriteLine("Server: Attempting to get client token...");
                clientToken = GetClientToken();
                Console.WriteLine("Server: Client token obtained. Attempting to deserialize request from pipe...");
                var request = await ReadMessageAsync<SudoRequest>(_commandPipe, _jsonOptions);
                Console.WriteLine("Server: Request deserialized from pipe.");
                if (request == null)
                {
                    Console.WriteLine("Server: Received null request.");
                    await SendErrorResponse("error", "Received empty or invalid request from client.");
                    return;
                }
                Log($"SudoRequestWorker: Received request mode: {request.Mode}");
                Log("SudoRequestWorker: Evaluating request mode...");
        
                if (request.Mode.Equals("sudo", StringComparison.OrdinalIgnoreCase))
                {
                    Console.WriteLine("Server: mode: sudo.");
                    userToken = await GetSudoTokenAsync(clientToken, request);
                }
                else if (request.Mode.Equals("su", StringComparison.OrdinalIgnoreCase))
                {
                    Log("SudoRequestWorker: Mode is 'su'.");
                    Console.WriteLine("Server: mode: su.");
                    userToken = await GetSuTokenAsync(clientToken, request);
                }
                else
                {
                    await SendErrorResponse("error", $"Invalid mode: {request.Mode}");
                    return;
                }
        
                if (userToken == IntPtr.Zero)
                {
                    return; // Auth failed, response already sent.
                }
        
                var options = new ProcessSpawnerOptions { WorkingDirectory = "C:\\" };
                sudoProcess = _processSpawner.Spawn(userToken, request.Command, options);
        
                var successResponse = new SudoServerResponse
                {
                    Status = "success_proceed_to_io",
                    StdinPipeName = sudoProcess.StdinPipeName,
                    StdoutPipeName = sudoProcess.StdoutPipeName,
                    StderrPipeName = sudoProcess.StderrPipeName
                };
                Console.WriteLine("Server: Attempting to serialize success response to pipe...");
                await WriteMessageAsync(_commandPipe, successResponse, _jsonOptions);
                Console.WriteLine("Server: Success response serialized. Waiting for pipe drain...");
                _commandPipe.WaitForPipeDrain();
                Console.WriteLine("Server: Pipe drained.");
        
                // The SudoProcess object is now responsible for managing its internal pipes and I/O forwarding.
                // We just need to wait for the helper process to complete its work.
                await Task.Run(() => sudoProcess.Process.WaitForExit());
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"ERROR handling request: {ex.Message}");
                if (_commandPipe.IsConnected)
                {
                    await SendErrorResponse("error", $"Server error: {ex.Message}");
                }
            }
            finally
            {
                if (clientToken != IntPtr.Zero) NativeMethods.CloseHandle(clientToken);
                if (userToken != IntPtr.Zero) NativeMethods.CloseHandle(userToken);
                sudoProcess?.Dispose();
                _commandPipe.Dispose(); // Ensure the command pipe is always disposed.
            }
        }




        private async Task WriteMessageAsync<T>(Stream stream, T message, JsonSerializerOptions options)
        {
            using (var ms = new MemoryStream())
            {
                await JsonSerializer.SerializeAsync(ms, message, options);
                var bytes = ms.ToArray();

                Log($"Server: WriteMessageAsync: Attempting to write message of type {typeof(T).Name}.");
                Log($"Server: WriteMessageAsync: Message payload length: {bytes.Length} bytes.");

                // Use BinaryWriter for ALL writes to the stream
                using (var bw = new BinaryWriter(stream, Encoding.UTF8, leaveOpen: true))
                {
                    bw.Write(bytes.Length); // Writes the 4-byte length prefix
                    bw.Write(bytes);        // Writes the actual message payload
                    bw.Flush();             // Ensure all buffered data is written to the underlying stream
                }
                Log("Server: WriteMessageAsync: Message written and flushed.");
            }
        }

        private async Task<T?> ReadMessageAsync<T>(Stream stream, JsonSerializerOptions options)
        {
            Log($"Server: ReadMessageAsync: Attempting to read message of type {typeof(T).Name}.");
            int length;
            byte[] messageBytes;

            // Use BinaryReader for ALL reads from the stream
            using (var br = new BinaryReader(stream, Encoding.UTF8, leaveOpen: true))
            {
                try
                {
                    length = br.ReadInt32(); // Reads 4 bytes as int (little-endian by default)
                }
                catch (EndOfStreamException)
                {
                    Log("Server: ReadMessageAsync: End of stream reached while reading length.");
                    return default(T); // Pipe closed prematurely
                }
                Log($"Server: ReadMessageAsync: Message length is {length} bytes.");
                if (length <= 0) throw new IOException("Invalid message length.");

                messageBytes = br.ReadBytes(length); // Reads the actual message payload
                if (messageBytes.Length != length)
                {
                    throw new IOException("Pipe closed prematurely or failed to read full message.");
                }
            }

            using (var ms = new MemoryStream(messageBytes))
            {
                Log("Server: ReadMessageAsync: Deserializing message.");
                return await JsonSerializer.DeserializeAsync<T>(ms, options);
            }
        }

        private IntPtr GetClientToken()
        {
            if (!NativeMethods.GetNamedPipeClientProcessId(_commandPipe.SafePipeHandle.DangerousGetHandle(), out uint clientProcessId))
            {
                throw new System.ComponentModel.Win32Exception();
            }

            IntPtr hClientProcess = NativeMethods.OpenProcess(0x1000, false, clientProcessId); // PROCESS_QUERY_LIMITED_INFORMATION
            if (hClientProcess == IntPtr.Zero) throw new System.ComponentModel.Win32Exception();
            try
            {
                if (!NativeMethods.OpenProcessToken(hClientProcess, NativeMethods.TokenAccessFlags.TOKEN_QUERY | NativeMethods.TokenAccessFlags.TOKEN_DUPLICATE, out IntPtr clientToken))
                {
                    throw new System.ComponentModel.Win32Exception();
                }
                return clientToken;
            }
            finally
            {
                NativeMethods.CloseHandle(hClientProcess);
            }
        }

        private uint GetSessionIdFromToken(IntPtr token)
        {
            uint sessionId = 0;
            uint returnLength = 0;
            IntPtr pSessionId = Marshal.AllocHGlobal(sizeof(uint));
            try
            {
                if (NativeMethods.GetTokenInformation(token, NativeMethods.TOKEN_INFORMATION_CLASS.TokenSessionId, pSessionId, sizeof(uint), out returnLength))
                {
                    sessionId = (uint)Marshal.ReadInt32(pSessionId);
                }
                else
                {
                    throw new System.ComponentModel.Win32Exception();
                }
            }
            finally
            {
                Marshal.FreeHGlobal(pSessionId);
            }
            return sessionId;
        }

        private async Task<IntPtr> GetSudoTokenAsync(IntPtr clientToken, SudoRequest request)
        {
            // Always challenge for password in sudo mode
            var challengeResponse = new SudoServerResponse { Status = "authentication_required" };
            await WriteMessageAsync(_commandPipe, challengeResponse, _jsonOptions);
            _commandPipe.WaitForPipeDrain();

            var authRequest = await ReadMessageAsync<SudoRequest>(_commandPipe, _jsonOptions);
            if (authRequest == null || authRequest.Password == null)
            {
                await SendErrorResponse("authentication_failure", "Password not provided or invalid authentication request.");
                return IntPtr.Zero;
            }

            // Validate the user's password and get a token
            IntPtr authenticatedToken = ValidateUserPassword(clientToken, authRequest.Password);
            if (authenticatedToken == IntPtr.Zero)
            {
                await SendErrorResponse("authentication_failure", "Invalid password.");
                return IntPtr.Zero;
            }

            // Return the authenticated token. The spawned process will run with the privileges of this token.
            // If the authenticated user is an administrator, the process will run elevated.
            // If not, it will run with standard user privileges.

            // After successful authentication, try to get the linked (elevated) token if UAC is active.
            IntPtr finalToken = authenticatedToken;
            if (authenticatedToken != IntPtr.Zero)
            {
                Log($"GetSudoTokenAsync: Attempting to get elevated token for authenticatedToken: {authenticatedToken}");
                IntPtr elevatedToken = GetElevatedToken(authenticatedToken);
                if (elevatedToken != IntPtr.Zero)
                {
                    Log($"GetSudoTokenAsync: Successfully obtained elevated token: {elevatedToken}. Closing original token: {authenticatedToken}");
                    NativeMethods.CloseHandle(authenticatedToken); // Close the original filtered token
                    finalToken = elevatedToken;
                }
                else
                {
                    Log($"GetSudoTokenAsync: Failed to obtain elevated token. Using original authenticatedToken: {authenticatedToken}");
                }
            }

            return finalToken;
        }

        private async Task<IntPtr> GetSuTokenAsync(IntPtr clientToken, SudoRequest request)
        {
            // Check for null TargetUser at the beginning
            if (request.TargetUser == null)
            {
                await SendErrorResponse("error", "Target user not specified for 'su' mode.");
                return IntPtr.Zero;
            }

            // Get SID of the client token's user
            IntPtr clientUserSid = IntPtr.Zero;
            try
            {
                uint tokenInfoLength = 0;
                NativeMethods.GetTokenInformation(clientToken, NativeMethods.TOKEN_INFORMATION_CLASS.TokenUser, IntPtr.Zero, tokenInfoLength, out tokenInfoLength);
                IntPtr pUser = Marshal.AllocHGlobal((int)tokenInfoLength);
                if (!NativeMethods.GetTokenInformation(clientToken, NativeMethods.TOKEN_INFORMATION_CLASS.TokenUser, pUser, tokenInfoLength, out tokenInfoLength)) throw new System.ComponentModel.Win32Exception();
                var tokenUser = (NativeMethods.TOKEN_USER)Marshal.PtrToStructure(pUser, typeof(NativeMethods.TOKEN_USER))!;
                clientUserSid = tokenUser.User.Sid;
                Marshal.FreeHGlobal(pUser); // Free the allocated memory for pUser
            }
            catch (Exception ex)
            {
                Log($"ERROR: GetSuTokenAsync: Failed to get client user SID: {ex.Message}");
                await SendErrorResponse("error", $"Failed to get client user SID: {ex.Message}");
                return IntPtr.Zero;
            }

            // Get SID of the target user
            IntPtr targetUserSid = IntPtr.Zero;
            try
            {
                uint sidSize = 0;
                uint domainSize = 0;
                NativeMethods.SID_NAME_USE sidUse;
                StringBuilder domainName = new StringBuilder();

                // First call to get buffer sizes
                NativeMethods.LookupAccountName(null, request.TargetUser, IntPtr.Zero, ref sidSize, domainName, ref domainSize, out sidUse);

                targetUserSid = Marshal.AllocHGlobal((int)sidSize);
                domainName = new StringBuilder((int)domainSize);

                // Second call to get the actual SID
                if (!NativeMethods.LookupAccountName(null, request.TargetUser, targetUserSid, ref sidSize, domainName, ref domainSize, out sidUse))
                {
                    Log($"ERROR: GetSuTokenAsync: LookupAccountName for {request.TargetUser} failed. LastWin32Error: {Marshal.GetLastWin32Error()}");
                    await SendErrorResponse("error", $"Failed to resolve target user: {request.TargetUser}. Win32 Error: {Marshal.GetLastWin32Error()}");
                    return IntPtr.Zero;
                }
            }
            catch (Exception ex)
            {
                Log($"ERROR: GetSuTokenAsync: Failed to get target user SID: {ex.Message}");
                await SendErrorResponse("error", $"Failed to get target user SID: {ex.Message}");
                return IntPtr.Zero;
            }

            // Compare SIDs
            bool isSameUser = NativeMethods.EqualSid(clientUserSid, targetUserSid);
            Marshal.FreeHGlobal(targetUserSid); // Free targetUserSid as it's no longer needed

            if (clientIsAdmin && isSameUser)
            {
                Log($"GetSuTokenAsync: Client is admin and target user is same. Returning client token.");
                // If the client is an admin and wants to su to themselves, return their token.
                // We can return the original clientToken or its elevated version if needed.
                // For now, just return the clientToken.
                return clientToken;
            }
            else if (clientIsAdmin && !isSameUser)
            {
                // If client is admin but wants to su to a different user,
                // we still need password for the target user.
                Log($"GetSuTokenAsync: Client is admin but target user is different. Proceeding with password authentication for {request.TargetUser}.");
            }
            else
            {
                // Client is not admin, proceed with password authentication.
                Log($"GetSuTokenAsync: Client is not admin. Proceeding with password authentication for {request.TargetUser}.");
            }

            // Proceed with password authentication for target user
            var challengeResponse = new SudoServerResponse { Status = "authentication_required" };
            Log("GetSuTokenAsync: Sending authentication challenge to client.");
            await WriteMessageAsync(_commandPipe, challengeResponse, _jsonOptions);
            Log("GetSuTokenAsync: Authentication challenge sent. Waiting for pipe drain.");
            _commandPipe.WaitForPipeDrain();
            Log("GetSuTokenAsync: Pipe drained. Attempting to deserialize authentication request.");
            var authRequest = await ReadMessageAsync<SudoRequest>(_commandPipe, _jsonOptions);
            Log("GetSuTokenAsync: Authentication request deserialized.");
            if (authRequest == null)
            {
                await SendErrorResponse("error", "Received empty or invalid authentication request.");
                return IntPtr.Zero;
            }

            // Check for null Password here
            if (authRequest.Password == null)
            {
                await SendErrorResponse("authentication_failure", "Password not provided.");
                return IntPtr.Zero;
            }

            string username;
            string domain;

            int backslashIndex = request.TargetUser.IndexOf('\');
            if (backslashIndex != -1)
            {
                domain = request.TargetUser.Substring(0, backslashIndex);
                username = request.TargetUser.Substring(backslashIndex + 1);
            }
            else
            {
                // No domain specified in username, assume local machine or default domain
                username = request.TargetUser;
                domain = "."; // Or string.Empty, depending on desired behavior for local accounts
            }

            Log($"GetSuTokenAsync: Attempting interactive logon for user: {username}, domain: {domain} , LogonType: {NativeMethods.LogonType.LOGON32_LOGON_INTERACTIVE}");
            if (NativeMethods.LogonUserW(username, domain, authRequest.Password, NativeMethods.LogonType.LOGON32_LOGON_INTERACTIVE, NativeMethods.LogonProvider.LOGON32_PROVIDER_DEFAULT, out IntPtr hSuToken))
            {
                Log($"GetSuTokenAsync: Interactive logon successful for {request.TargetUser}. Token: {hSuToken}");
                return hSuToken;
            }
            int lastErrorAuth = Marshal.GetLastWin32Error();
            Log($"ERROR: GetSuTokenAsync: Interactive logon failed for {request.TargetUser}. LastWin32Error: {lastErrorAuth}");
            await SendErrorResponse("authentication_failure", $"Invalid username or password. Win32 Error: {lastErrorAuth}");
            return IntPtr.Zero;
        }
