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
        
                if (request.Mode.Equals("sudo", StringComparison.OrdinalIgnoreCase))
                {
                    Console.WriteLine("Server: mode: sudo.");
                    userToken = await GetSudoTokenAsync(clientToken, request);
                }
                else if (request.Mode.Equals("su", StringComparison.OrdinalIgnoreCase))
                {
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
                var lengthBytes = BitConverter.GetBytes(bytes.Length);

                await stream.WriteAsync(lengthBytes, 0, lengthBytes.Length);
                await stream.WriteAsync(bytes, 0, bytes.Length);
                await stream.FlushAsync();
            }
        }

        private async Task<T?> ReadMessageAsync<T>(Stream stream, JsonSerializerOptions options)
        {
            var lengthBytes = new byte[4];
            var bytesRead = await stream.ReadAsync(lengthBytes, 0, lengthBytes.Length);
            if (bytesRead == 0) return default(T);
            if (bytesRead != 4) throw new IOException("Failed to read message length.");

            var length = BitConverter.ToInt32(lengthBytes, 0);
            if (length <= 0) throw new IOException("Invalid message length.");

            var messageBytes = new byte[length];
            bytesRead = 0;
            while (bytesRead < length)
            {
                var currentRead = await stream.ReadAsync(messageBytes, bytesRead, length - bytesRead);
                if (currentRead == 0) throw new IOException("Pipe closed prematurely.");
                bytesRead += currentRead;
            }

            using (var ms = new MemoryStream(messageBytes))
            {
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

            Log($"GetSudoTokenAsync: Authenticated token obtained: {authenticatedToken}. Checking if admin...");
            bool isAdmin = IsTokenAdmin(authenticatedToken);
            Log($"GetSudoTokenAsync: IsTokenAdmin returned: {isAdmin}");
            // If the authenticated user is an administrator, try to get the linked (elevated) token.
            if (isAdmin)
            {
                IntPtr elevatedToken = GetElevatedToken(authenticatedToken);
                if (elevatedToken != IntPtr.Zero)
                {
                    // Close the original authenticatedToken as we are returning the elevated one.
                    NativeMethods.CloseHandle(authenticatedToken);
                    return elevatedToken;
                }
            }

            return authenticatedToken;
        }

        private async Task<IntPtr> GetSuTokenAsync(IntPtr clientToken, SudoRequest request)
        {
            // Check for null TargetUser at the beginning
            if (request.TargetUser == null)
            {
                await SendErrorResponse("error", "Target user not specified for 'su' mode.");
                return IntPtr.Zero;
            }

            if (IsClientAdmin(clientToken))
            {
                // Line 160
                if (NativeMethods.LogonUserW(request.TargetUser, ".", "", NativeMethods.LogonType.LOGON32_LOGON_BATCH, NativeMethods.LogonProvider.LOGON32_PROVIDER_DEFAULT, out IntPtr hToken)) return hToken;
                await SendErrorResponse("error", "Passwordless su failed.");
                return IntPtr.Zero;
            }
            var challengeResponse = new SudoServerResponse { Status = "authentication_required" };
            await JsonSerializer.SerializeAsync(_commandPipe, challengeResponse, _jsonOptions);
            _commandPipe.WaitForPipeDrain();
            var authRequest = await JsonSerializer.DeserializeAsync<SudoRequest>(_commandPipe, _jsonOptions);
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

            // Line 168
            if (NativeMethods.LogonUserW(request.TargetUser, ".", authRequest.Password, NativeMethods.LogonType.LOGON32_LOGON_INTERACTIVE, NativeMethods.LogonProvider.LOGON32_PROVIDER_DEFAULT, out IntPtr hSuToken)) return hSuToken;
            await SendErrorResponse("authentication_failure", "Invalid username or password.");
            return IntPtr.Zero;
        }

        private bool IsClientAdmin(IntPtr clientToken)
        {
            var adminSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            byte[] adminSidBytes = new byte[adminSid.BinaryLength];
            adminSid.GetBinaryForm(adminSidBytes, 0);
            IntPtr pAdminSid = Marshal.AllocHGlobal(adminSidBytes.Length);
            Marshal.Copy(adminSidBytes, 0, pAdminSid, adminSidBytes.Length);
            try
            {
                if (NativeMethods.CheckTokenMembership(clientToken, pAdminSid, out bool isAdmin)) return isAdmin;
                return false;
            }
            finally
            {
                Marshal.FreeHGlobal(pAdminSid);
            }
        }

        private IntPtr ValidateUserPassword(IntPtr clientToken, string password)
        {
            IntPtr pUser = IntPtr.Zero;
            try
            {
                uint tokenInfoLength = 0;
                NativeMethods.GetTokenInformation(clientToken, NativeMethods.TOKEN_INFORMATION_CLASS.TokenUser, IntPtr.Zero, tokenInfoLength, out tokenInfoLength);
                pUser = Marshal.AllocHGlobal((int)tokenInfoLength);
                if (!NativeMethods.GetTokenInformation(clientToken, NativeMethods.TOKEN_INFORMATION_CLASS.TokenUser, pUser, tokenInfoLength, out tokenInfoLength)) throw new System.ComponentModel.Win32Exception();
                var tokenUser = (NativeMethods.TOKEN_USER)Marshal.PtrToStructure(pUser, typeof(NativeMethods.TOKEN_USER))!;
                uint cchName = 0, cchReferencedDomainName = 0;
                NativeMethods.LookupAccountSid(null, tokenUser.User.Sid, null, ref cchName, null, ref cchReferencedDomainName, out _);
                var name = new StringBuilder((int)cchName);
                var domain = new StringBuilder((int)cchReferencedDomainName);
                if (!NativeMethods.LookupAccountSid(null, tokenUser.User.Sid, name, ref cchName, domain, ref cchReferencedDomainName, out _)) throw new System.ComponentModel.Win32Exception();
                if (NativeMethods.LogonUserW(name.ToString(), domain.ToString(), password, NativeMethods.LogonType.LOGON32_LOGON_INTERACTIVE, NativeMethods.LogonProvider.LOGON32_PROVIDER_DEFAULT, out IntPtr hToken))
                {
                    return hToken;
                }
                return IntPtr.Zero;
            }
            finally
            {
                if (pUser != IntPtr.Zero) Marshal.FreeHGlobal(pUser);
            }
        }

        private IntPtr GetElevatedToken(IntPtr clientToken)
        {
            Log($"GetElevatedToken: Attempting to get elevated token for clientToken: {clientToken}");
            uint returnLength;
            IntPtr linkedTokenPtr = IntPtr.Zero;
            try
            {
                Log("GetElevatedToken: Calling GetTokenInformation for TokenLinkedToken (first call to get length).");
                bool success = NativeMethods.GetTokenInformation(clientToken, NativeMethods.TOKEN_INFORMATION_CLASS.TokenLinkedToken, IntPtr.Zero, 0, out returnLength);
                Log($"GetElevatedToken: GetTokenInformation (first call) success: {success}, returnLength: {returnLength}, LastWin32Error: {Marshal.GetLastWin32Error()}");

                if (returnLength > 0)
                {
                    linkedTokenPtr = Marshal.AllocHGlobal((int)returnLength);
                    Log($"GetElevatedToken: Allocated memory for linked token at {linkedTokenPtr}. Calling GetTokenInformation (second call).");
                    success = NativeMethods.GetTokenInformation(clientToken, NativeMethods.TOKEN_INFORMATION_CLASS.TokenLinkedToken, linkedTokenPtr, returnLength, out returnLength);
                    Log($"GetElevatedToken: GetTokenInformation (second call) success: {success}, LastWin32Error: {Marshal.GetLastWin32Error()}");

                    if (success)
                    {
                        object obj = Marshal.PtrToStructure(linkedTokenPtr, typeof(NativeMethods.TOKEN_LINKED_TOKEN))!;
                        if (obj != null)
                        {
                            var linkedTokenStruct = (NativeMethods.TOKEN_LINKED_TOKEN)obj!;
                            Log($"GetElevatedToken: LinkedToken struct obtained. LinkedToken: {linkedTokenStruct.LinkedToken}");
                            if (linkedTokenStruct.LinkedToken != IntPtr.Zero)
                            {
                                Log($"GetElevatedToken: Successfully retrieved linked token: {linkedTokenStruct.LinkedToken}");
                                return linkedTokenStruct.LinkedToken;
                            }
                            else
                            {
                                Log("GetElevatedToken: LinkedToken is IntPtr.Zero. No linked token found.");
                            }
                        }
                        else
                        {
                            Log("WARNING: Marshal.PtrToStructure returned null for TOKEN_LINKED_TOKEN.");
                        }
                    }
                }
                else
                {
                    Log("GetElevatedToken: GetTokenInformation (first call) returned 0 length. No linked token information available.");
                }
            }
            catch (Exception ex)
            {
                Log($"ERROR in GetElevatedToken (TokenLinkedToken part): {ex.Message}, LastWin32Error: {Marshal.GetLastWin32Error()}");
            }
            finally
            {
                if (linkedTokenPtr != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(linkedTokenPtr);
                    Log("GetElevatedToken: Freed linkedTokenPtr.");
                }
            }

            Log("GetElevatedToken: Falling back to DuplicateTokenEx.");
            IntPtr duplicatedToken = IntPtr.Zero;
            var sa = new NativeMethods.SECURITY_ATTRIBUTES();
            sa.nLength = Marshal.SizeOf(sa);
            sa.bInheritHandle = false;
            bool duplicateSuccess = NativeMethods.DuplicateTokenEx(clientToken, NativeMethods.TokenAccessFlags.TOKEN_ALL_ACCESS, ref sa, NativeMethods.SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, NativeMethods.TOKEN_TYPE.TokenPrimary, out duplicatedToken);
            Log($"GetElevatedToken: DuplicateTokenEx success: {duplicateSuccess}, duplicatedToken: {duplicatedToken}, LastWin32Error: {Marshal.GetLastWin32Error()}");
            if (duplicateSuccess)
            {
                Log($"GetElevatedToken: Returning duplicated token: {duplicatedToken}");
                return duplicatedToken;
            }
            Log("GetElevatedToken: DuplicateTokenEx failed. Returning IntPtr.Zero.");
            return IntPtr.Zero;
        }

        private async Task SendErrorResponse(string status, string message)
        {
            Console.WriteLine($"Server: Sending error response - Status: {status}, Message: {message}");
            var errorResponse = new SudoServerResponse { Status = status, ErrorMessage = message };
            await WriteMessageAsync(_commandPipe, errorResponse, _jsonOptions);
            _commandPipe.WaitForPipeDrain();
            Console.WriteLine("Server: Error response sent and pipe drained.");
        }

        private bool IsTokenAdmin(IntPtr token)
        {
            var adminSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            byte[] adminSidBytes = new byte[adminSid.BinaryLength];
            adminSid.GetBinaryForm(adminSidBytes, 0);
            IntPtr pAdminSid = Marshal.AllocHGlobal(adminSidBytes.Length);
            Marshal.Copy(adminSidBytes, 0, pAdminSid, adminSidBytes.Length);
            try
            {
                if (NativeMethods.CheckTokenMembership(token, pAdminSid, out bool isAdmin)) return isAdmin;
                return false;
            }
            finally
            {
                Marshal.FreeHGlobal(pAdminSid);
            }
        }

    }
}
