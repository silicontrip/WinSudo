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
            // Enable necessary privileges for the service process
            bool impersonatePrivilegeEnabled = EnablePrivilege("SeImpersonatePrivilege");
            bool assignPrimaryTokenPrivilegeEnabled = EnablePrivilege("SeAssignPrimaryTokenPrivilege");
            Log($"HandleRequestAsync: SeImpersonatePrivilege enabled: {impersonatePrivilegeEnabled}");
            Log($"HandleRequestAsync: SeAssignPrimaryTokenPrivilege enabled: {assignPrimaryTokenPrivilegeEnabled}");

            IntPtr clientToken = IntPtr.Zero;
            IntPtr userToken = IntPtr.Zero;
            SudoProcess sudoProcess = null!;
 
            try
            {
                //Log("SudoRequestWorker: HandleRequestAsync entered.");
                //Console.WriteLine("Server: HandleRequestAsync started.");
                //Console.WriteLine("Server: Attempting to get client token...");
                clientToken = GetClientToken();
                uint clientSessionId = GetSessionIdFromToken(clientToken);
                //Console.WriteLine("Server: Client token obtained. Attempting to deserialize request from pipe...");
                var request = await ReadMessageAsync<SudoRequest>(_commandPipe, _jsonOptions);
                //Console.WriteLine("Server: Request deserialized from pipe.");
                if (request == null)
                {
                    Console.WriteLine("Server: Received null request.");
                    await SendErrorResponse("error", "Received empty or invalid request from client.");
                    return;
                }
                //Log($"SudoRequestWorker: Received request mode: {request.Mode}");
                //Log("SudoRequestWorker: Evaluating request mode...");
        
                if (request.Mode.Equals("sudo", StringComparison.OrdinalIgnoreCase))
                {
                    //Console.WriteLine("Server: mode: sudo.");
                    userToken = await GetSudoTokenAsync(clientToken, request);
                }
                else if (request.Mode.Equals("su", StringComparison.OrdinalIgnoreCase))
                {
                    //Log("SudoRequestWorker: Mode is 'su'.");
                    //Console.WriteLine("Server: mode: su.");
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
        
                uint targetSessionId = request.SessionId ?? clientSessionId;
                var options = new ProcessSpawnerOptions { WorkingDirectory = "C:\\", SessionId = targetSessionId };
                
                try
                {
                    Log($"HandleRequestAsync: Attempting to spawn process with userToken: {userToken}, command: {request.Command}, sessionId: {targetSessionId}");
                    sudoProcess = _processSpawner.Spawn(userToken, request.Command, options);
                    Log($"HandleRequestAsync: Process spawned successfully. StdinPipe: {sudoProcess.StdinPipeName}");
                }
                catch (Exception ex)
                {
                    Log($"HandleRequestAsync: Exception during process spawn: {ex.Message}");
                    await SendErrorResponse("error", $"Failed to spawn process: {ex.Message}");
                    return;
                }

                var successResponse = new SudoServerResponse
                {
                    Status = "success_proceed_to_io",
                    StdinPipeName = sudoProcess.StdinPipeName,
                    StdoutPipeName = sudoProcess.StdoutPipeName,
                    StderrPipeName = sudoProcess.StderrPipeName
                };
                //Console.WriteLine("Server: Attempting to serialize success response to pipe...");
                await WriteMessageAsync(_commandPipe, successResponse, _jsonOptions);
                //Console.WriteLine("Server: Success response serialized. Waiting for pipe drain...");
                _commandPipe.WaitForPipeDrain();
                //Console.WriteLine("Server: Pipe drained.");
        
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

                //Log($"Server: WriteMessageAsync: Attempting to write message of type {typeof(T).Name}.");
                //Log($"Server: WriteMessageAsync: Message payload length: {bytes.Length} bytes.");

                // Use BinaryWriter for ALL writes to the stream
                using (var bw = new BinaryWriter(stream, Encoding.UTF8, leaveOpen: true))
                {
                    bw.Write(bytes.Length); // Writes the 4-byte length prefix
                    bw.Write(bytes);        // Writes the actual message payload
                    bw.Flush();             // Ensure all buffered data is written to the underlying stream
                }
                //Log("Server: WriteMessageAsync: Message written and flushed.");
            }
        }

        private async Task<T?> ReadMessageAsync<T>(Stream stream, JsonSerializerOptions options)
        {
            //Log($"Server: ReadMessageAsync: Attempting to read message of type {typeof(T).Name}.");
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
                    //Log("Server: ReadMessageAsync: End of stream reached while reading length.");
                    return default(T); // Pipe closed prematurely
                }
                //Log($"Server: ReadMessageAsync: Message length is {length} bytes.");
                if (length <= 0) throw new IOException("Invalid message length.");

                messageBytes = br.ReadBytes(length); // Reads the actual message payload
                if (messageBytes.Length != length)
                {
                    throw new IOException("Pipe closed prematurely or failed to read full message.");
                }
            }

            using (var ms = new MemoryStream(messageBytes))
            {
                //Log("Server: ReadMessageAsync: Deserializing message.");
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
                try
                {
                    //Log($"GetSudoTokenAsync: Attempting to get elevated token for authenticatedToken: {authenticatedToken}");
                    IntPtr elevatedToken = GetElevatedToken(authenticatedToken);
                    if (elevatedToken != IntPtr.Zero)
                    {
                        //Log($"GetSudoTokenAsync: Successfully obtained elevated token: {elevatedToken}. Closing original token: {authenticatedToken}");
                        NativeMethods.CloseHandle(authenticatedToken); // Close the original filtered token
                        finalToken = elevatedToken;
                    }
                    else
                    {
                        Log($"GetSudoTokenAsync: GetElevatedToken returned IntPtr.Zero. Using original authenticatedToken: {authenticatedToken}");
                    }
                }
                catch (Exception ex)
                {
                    Log($"GetSudoTokenAsync: Exception during GetElevatedToken: {ex.Message}");
                    // Optionally, decide if you want to proceed with the original token or fail
                    // For now, we'll proceed with the original token if elevation fails due to exception
                    finalToken = authenticatedToken;
                }
            }

            // Ensure the token is associated with the target session ID
            if (request.SessionId.HasValue)
            {
                uint targetSessionId = request.SessionId.Value;
                if (!NativeMethods.SetTokenInformation(finalToken, NativeMethods.TOKEN_INFORMATION_CLASS.TokenSessionId, ref targetSessionId, sizeof(uint)))
                {
                    int lastError = Marshal.GetLastWin32Error();
                    Log($"GetSudoTokenAsync: Failed to set token session ID to {targetSessionId}. LastWin32Error: {lastError}");
                    NativeMethods.CloseHandle(finalToken); // Close token if we can't set session
                    return IntPtr.Zero;
                }
                Log($"GetSudoTokenAsync: Successfully set token session ID to {targetSessionId}.");
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
                //Log($"ERROR: GetSuTokenAsync: Failed to get client user SID: {ex.Message}");
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
                    //Log($"ERROR: GetSuTokenAsync: LookupAccountName for {request.TargetUser} failed. LastWin32Error: {Marshal.GetLastWin32Error()}");
                    await SendErrorResponse("error", $"Failed to resolve target user: {request.TargetUser}. Win32 Error: {Marshal.GetLastWin32Error()}");
                    return IntPtr.Zero;
                }
            }
            catch (Exception ex)
            {
                //Log($"ERROR: GetSuTokenAsync: Failed to get target user SID: {ex.Message}");
                await SendErrorResponse("error", $"Failed to get target user SID: {ex.Message}");
                return IntPtr.Zero;
            }

            // Compare SIDs
            bool isSameUser = NativeMethods.EqualSid(clientUserSid, targetUserSid);
            Marshal.FreeHGlobal(targetUserSid); // Free targetUserSid as it's no longer needed

            bool clientIsAdminElevated = false;
            if (NativeMethods.ImpersonateLoggedOnUser(clientToken))
            {
                try
                {
                    clientIsAdminElevated = IsClientAdmin(clientToken);
                }
                finally
                {
                    NativeMethods.RevertToSelf();
                }
            }
            else
            {
                int lastError = Marshal.GetLastWin32Error();
                Log($"GetSuTokenAsync: Failed to impersonate client token. LastWin32Error: {lastError}");
            }

            if (clientIsAdminElevated && isSameUser)
            {
                Log($"GetSuTokenAsync: Client is admin and target user is same. Returning client token.");
                return clientToken;
            }
            else if (clientIsAdminElevated && !isSameUser)
            {
                Log($"GetSuTokenAsync: Client is admin and target user is different. Target: {request.TargetUser}");
                // Check for well-known system accounts
                IntPtr systemToken = IntPtr.Zero;
                if (request.TargetUser.Equals("NT AUTHORITY\\SYSTEM", StringComparison.OrdinalIgnoreCase) ||
                    request.TargetUser.Equals("SYSTEM", StringComparison.OrdinalIgnoreCase))
                {
                    Log("GetSuTokenAsync: Attempting to get token for SYSTEM account.");
                    systemToken = GetTokenForSystemAccount("SYSTEM");
                }
                else if (request.TargetUser.Equals("NT AUTHORITY\\LOCAL SERVICE", StringComparison.OrdinalIgnoreCase) ||
                         request.TargetUser.Equals("LOCAL SERVICE", StringComparison.OrdinalIgnoreCase))
                {
                    Log("GetSuTokenAsync: Attempting to get token for LOCAL SERVICE account.");
                    systemToken = GetTokenForSystemAccount("LOCAL SERVICE");
                }
                else if (request.TargetUser.Equals("NT AUTHORITY\\NETWORK SERVICE", StringComparison.OrdinalIgnoreCase) ||
                         request.TargetUser.Equals("NETWORK SERVICE", StringComparison.OrdinalIgnoreCase))
                {
                    Log("GetSuTokenAsync: Attempting to get token for NETWORK SERVICE account.");
                    systemToken = GetTokenForSystemAccount("NETWORK SERVICE");
                }

                if (systemToken != IntPtr.Zero)
                {
                    Log($"GetSuTokenAsync: Successfully obtained token for {request.TargetUser} without password.");
                    // Ensure the token is associated with the target session ID
                    if (request.SessionId.HasValue)
                    {
                        uint targetSessionId = request.SessionId.Value;
                        if (!NativeMethods.SetTokenInformation(systemToken, NativeMethods.TOKEN_INFORMATION_CLASS.TokenSessionId, ref targetSessionId, sizeof(uint)))
                        {
                            int lastError = Marshal.GetLastWin32Error();
                            Log($"GetSuTokenAsync: Failed to set token session ID to {targetSessionId}. LastWin32Error: {lastError}");
                            NativeMethods.CloseHandle(systemToken); // Close token if we can't set session
                            return IntPtr.Zero;
                        }
                        Log($"GetSuTokenAsync: Successfully set token session ID to {targetSessionId}.");
                    }
                    return systemToken;
                }
                else
                {
                    Log($"GetSuTokenAsync: Not a well-known system account or failed to get token without password. Proceeding with password authentication for {request.TargetUser}.");
                }
            }
            else
            {
                Log($"GetSuTokenAsync: Client is not admin. Proceeding with password authentication for {request.TargetUser}.");
            }
            // Proceed with password authentication for target user
            var challengeResponse = new SudoServerResponse { Status = "authentication_required" };
            //Log("GetSuTokenAsync: Sending authentication challenge to client.");
            await WriteMessageAsync(_commandPipe, challengeResponse, _jsonOptions);
            //Log("GetSuTokenAsync: Authentication challenge sent. Waiting for pipe drain.");
            _commandPipe.WaitForPipeDrain();
            //Log("GetSuTokenAsync: Pipe drained. Attempting to deserialize authentication request.");
            var authRequest = await ReadMessageAsync<SudoRequest>(_commandPipe, _jsonOptions);
            //Log("GetSuTokenAsync: Authentication request deserialized.");
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

            int backslashIndex = request.TargetUser.IndexOf('\\');
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

            //Log($"GetSuTokenAsync: Attempting interactive logon for user: {username}, domain: {domain} , LogonType: {NativeMethods.LogonType.LOGON32_LOGON_INTERACTIVE}");
            if (NativeMethods.LogonUserW(username, domain, authRequest.Password, NativeMethods.LogonType.LOGON32_LOGON_INTERACTIVE, NativeMethods.LogonProvider.LOGON32_PROVIDER_DEFAULT, out IntPtr hSuToken))
            {
                //Log($"GetSuTokenAsync: Interactive logon successful for {request.TargetUser}. Token: {hSuToken}");
                // Ensure the token is associated with the target session ID
                if (request.SessionId.HasValue)
                {
                    uint targetSessionId = request.SessionId.Value;
                    if (!NativeMethods.SetTokenInformation(hSuToken, NativeMethods.TOKEN_INFORMATION_CLASS.TokenSessionId, ref targetSessionId, sizeof(uint)))
                    {
                        int lastError = Marshal.GetLastWin32Error();
                        Log($"GetSuTokenAsync: Failed to set token session ID to {targetSessionId}. LastWin32Error: {lastError}");
                        NativeMethods.CloseHandle(hSuToken); // Close token if we can't set session
                        return IntPtr.Zero;
                    }
                    Log($"GetSuTokenAsync: Successfully set token session ID to {targetSessionId}.");
                }
                return hSuToken;
            }
            int lastErrorAuth = Marshal.GetLastWin32Error();
            // Log($"ERROR: GetSuTokenAsync: Interactive logon failed for {request.TargetUser}. LastWin32Error: {lastErrorAuth}");
            await SendErrorResponse("authentication_failure", $"Invalid username or password. Win32 Error: {lastErrorAuth}");
            return IntPtr.Zero;
        }

        private IntPtr ValidateUserPassword(IntPtr clientToken, string password)
        {
            // Get the username associated with the clientToken
            string fullUsername = GetUsernameFromToken(clientToken);
            if (string.IsNullOrEmpty(fullUsername))
            {
                Log("ValidateUserPassword: Could not get username from client token.");
                return IntPtr.Zero;
            }

            string username;
            string domain;

            int backslashIndex = fullUsername.IndexOf('\\');
            if (backslashIndex != -1)
            {
                domain = fullUsername.Substring(0, backslashIndex);
                username = fullUsername.Substring(backslashIndex + 1);
            }
            else
            {
                // No domain specified in username, assume local machine or default domain
                username = fullUsername;
                domain = "."; // Or string.Empty, depending on desired behavior for local accounts
            }

            Log($"ValidateUserPassword: Attempting LogonUser for user: {username}, domain: {domain}");
            if (NativeMethods.LogonUserW(username, domain, password,
                                         NativeMethods.LogonType.LOGON32_LOGON_INTERACTIVE,
                                         NativeMethods.LogonProvider.LOGON32_PROVIDER_DEFAULT,
                                         out IntPtr hToken))
            {
                Log($"ValidateUserPassword: LogonUser successful for {fullUsername}. Token: {hToken}");
                return hToken;
            }
            else
            {
                int lastError = Marshal.GetLastWin32Error();
                Log($"ValidateUserPassword: LogonUser failed for {fullUsername}. LastWin32Error: {lastError}");
                return IntPtr.Zero;
            }
        }

        private string GetUsernameFromToken(IntPtr token)
        {
            uint tokenInfoLength = 0;
            NativeMethods.GetTokenInformation(token, NativeMethods.TOKEN_INFORMATION_CLASS.TokenUser, IntPtr.Zero, tokenInfoLength, out tokenInfoLength);

            IntPtr pUser = Marshal.AllocHGlobal((int)tokenInfoLength);
            try
            {
                if (NativeMethods.GetTokenInformation(token, NativeMethods.TOKEN_INFORMATION_CLASS.TokenUser, pUser, tokenInfoLength, out tokenInfoLength))
                {
                    var tokenUser = (NativeMethods.TOKEN_USER)Marshal.PtrToStructure(pUser, typeof(NativeMethods.TOKEN_USER))!;
                    var sid = new SecurityIdentifier(tokenUser.User.Sid);
                    string username = sid.Translate(typeof(NTAccount)).Value;
                    Log($"GetUsernameFromToken: SID: {sid.Value}, Translated Username: {username}");
                    return username;
                }
            }
            finally
            {
                Marshal.FreeHGlobal(pUser);
            }
            Log("GetUsernameFromToken: Failed to get username from token.");
            return string.Empty;
        }

        

        private bool EnablePrivilege(string privilegeName)
        {
            IntPtr hToken = IntPtr.Zero;
            NativeMethods.LUID luid;

            if (!NativeMethods.OpenProcessToken(NativeMethods.GetCurrentProcess(),
                                                NativeMethods.TokenAccessFlags.TOKEN_ADJUST_PRIVILEGES | NativeMethods.TokenAccessFlags.TOKEN_QUERY,
                                                out hToken))
            {
                int lastError = Marshal.GetLastWin32Error();
                Log($"EnablePrivilege: OpenProcessToken failed. LastWin32Error: {lastError}");
                return false;
            }

            try
            {
                if (!NativeMethods.LookupPrivilegeValue(null, privilegeName, out luid))
                {
                    int lastError = Marshal.GetLastWin32Error();
                    Log($"EnablePrivilege: LookupPrivilegeValue for {privilegeName} failed. LastWin32Error: {lastError}");
                    return false;
                }

                NativeMethods.TOKEN_PRIVILEGES tp = new NativeMethods.TOKEN_PRIVILEGES();
                tp.PrivilegeCount = 1;
                tp.Privileges = new NativeMethods.LUID_AND_ATTRIBUTES[1];
                tp.Privileges[0].Luid = luid;
                tp.Privileges[0].Attributes = NativeMethods.SE_PRIVILEGE_ENABLED;

                if (!NativeMethods.AdjustTokenPrivileges(hToken, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero))
                {
                    int lastError = Marshal.GetLastWin32Error();
                    Log($"EnablePrivilege: AdjustTokenPrivileges for {privilegeName} failed. LastWin32Error: {lastError}");
                    return false;
                }

                Log($"EnablePrivilege: Successfully enabled privilege: {privilegeName}");
                return true;
            }
            finally
            {
                if (hToken != IntPtr.Zero)
                {
                    NativeMethods.CloseHandle(hToken);
                }
            }
        }

        private bool IsCurrentProcessSystem()
        {
            using (WindowsIdentity current = WindowsIdentity.GetCurrent())
            {
                return current.User?.IsWellKnown(WellKnownSidType.LocalSystemSid) == true;
            }
        }

        private IntPtr GetTokenForSystemAccount(string accountName)
        {
            Log($"GetTokenForSystemAccount: Attempting to get token for account: {accountName}");
            try
            {
                string username;
                string domain;
                NativeMethods.LogonType logonType;

                if (accountName.Equals("SYSTEM", StringComparison.OrdinalIgnoreCase))
                {
                    username = "SYSTEM";
                    domain = "NT AUTHORITY";
                    logonType = NativeMethods.LogonType.LOGON32_LOGON_SERVICE; // Or LOGON32_LOGON_BATCH
                }
                else if (accountName.Equals("LOCAL SERVICE", StringComparison.OrdinalIgnoreCase))
                {
                    username = "LOCAL SERVICE";
                    domain = "NT AUTHORITY";
                    logonType = NativeMethods.LogonType.LOGON32_LOGON_SERVICE;
                }
                else if (accountName.Equals("NETWORK SERVICE", StringComparison.OrdinalIgnoreCase))
                {
                    username = "NETWORK SERVICE";
                    domain = "NT AUTHORITY";
                    logonType = NativeMethods.LogonType.LOGON32_LOGON_SERVICE;
                }
                else
                {
                    Log($"GetTokenForSystemAccount: Not a recognized well-known system account: {accountName}");
                    return IntPtr.Zero;
                }

                Log($"GetTokenForSystemAccount: Attempting LogonUserW for {username}\\{domain} with null password and LogonType: {logonType}");
                IntPtr hToken = IntPtr.Zero;
                if (NativeMethods.LogonUserW(username, domain, null, logonType, NativeMethods.LogonProvider.LOGON32_PROVIDER_DEFAULT, out hToken))
                {
                    Log($"GetTokenForSystemAccount: LogonUserW successful for {accountName}. Token: {hToken}");
                    return hToken;
                }
                else
                {
                    int lastError = Marshal.GetLastWin32Error();
                    Log($"GetTokenForSystemAccount: LogonUserW failed for {accountName}. LastWin32Error: {lastError}");
                    return IntPtr.Zero;
                }
            }
            catch (Exception ex)
            {
                Log($"GetTokenForSystemAccount: General exception: {ex.Message}");
            }
            Log($"GetTokenForSystemAccount: Failed to get token for {accountName}.");
            return IntPtr.Zero;
        }

        private bool HasPrivilege(string privilegeName)
        {
            IntPtr hToken = IntPtr.Zero;
            try
            {
                if (!NativeMethods.OpenProcessToken(NativeMethods.GetCurrentProcess(),
                                                    NativeMethods.TokenAccessFlags.TOKEN_QUERY,
                                                    out hToken))
                {
                    int lastError = Marshal.GetLastWin32Error();
                    Log($"HasPrivilege: Failed to open process token. LastWin32Error: {lastError}");
                    return false;
                }

                NativeMethods.LUID luid;
                if (!NativeMethods.LookupPrivilegeValue(null, privilegeName, out luid))
                {
                    int lastError = Marshal.GetLastWin32Error();
                    Log($"HasPrivilege: Failed to lookup privilege value for {privilegeName}. LastWin32Error: {lastError}");
                    return false;
                }

                NativeMethods.TOKEN_PRIVILEGES tp = new NativeMethods.TOKEN_PRIVILEGES();
                tp.PrivilegeCount = 1;
                tp.Privileges = new NativeMethods.LUID_AND_ATTRIBUTES[1];
                tp.Privileges[0].Luid = luid;
                tp.Privileges[0].Attributes = NativeMethods.SE_PRIVILEGE_ENABLED; // Check if enabled

                if (!NativeMethods.AdjustTokenPrivileges(hToken, false, ref tp, (uint)Marshal.SizeOf(tp), IntPtr.Zero, IntPtr.Zero))
                {
                    int lastError = Marshal.GetLastWin32Error();
                    Log($"HasPrivilege: Failed to adjust token privileges for {privilegeName}. LastWin32Error: {lastError}");
                    return false;
                }

                // If AdjustTokenPrivileges succeeds, it means the privilege exists and we tried to enable it.
                // To check if it was already enabled, we need to call GetTokenInformation with TokenPrivileges.
                // However, for a simple check of presence, this is often sufficient.
                // A more robust check would involve getting the current privileges and checking the attributes.
                // For now, we'll assume if AdjustTokenPrivileges succeeds without error, the privilege is available.
                Log($"HasPrivilege: Privilege {privilegeName} is available.");
                return true;
            }
            finally
            {
                if (hToken != IntPtr.Zero)
                {
                    NativeMethods.CloseHandle(hToken);
                }
            }
        }

        private bool IsClientAdmin(IntPtr clientToken)
        {
            Log($"IsClientAdmin: Checking token {clientToken} for elevated administrator privileges.");
            uint returnLength = 0;
            IntPtr pElevationType = IntPtr.Zero;
            IntPtr pElevation = IntPtr.Zero;
            bool isElevated = false;

            try
            {
                // Get TokenElevationType
                NativeMethods.GetTokenInformation(clientToken, NativeMethods.TOKEN_INFORMATION_CLASS.TokenElevationType, IntPtr.Zero, 0, out returnLength);
                pElevationType = Marshal.AllocHGlobal((int)returnLength);
                if (!NativeMethods.GetTokenInformation(clientToken, NativeMethods.TOKEN_INFORMATION_CLASS.TokenElevationType, pElevationType, returnLength, out returnLength))
                {
                    Log($"IsClientAdmin: GetTokenInformation (TokenElevationType) failed. LastWin32Error: {Marshal.GetLastWin32Error()}");
                    return false;
                }
                NativeMethods.TOKEN_ELEVATION_TYPE elevationType = (NativeMethods.TOKEN_ELEVATION_TYPE)Marshal.ReadInt32(pElevationType);
                Log($"IsClientAdmin: TokenElevationType: {elevationType}");

                // If elevation type is full, it's elevated. If limited, it's not. Default means no UAC or not an admin.
                // If elevation type is full or limited, it's considered an administrator for this check.
                // Limited means the user is an admin, but running non-elevated.
                if (elevationType == NativeMethods.TOKEN_ELEVATION_TYPE.TokenElevationTypeFull ||
                    elevationType == NativeMethods.TOKEN_ELEVATION_TYPE.TokenElevationTypeLimited)
                {
                    isElevated = true;
                }
                else if (elevationType == NativeMethods.TOKEN_ELEVATION_TYPE.TokenElevationTypeDefault)
                {
                    // Default token type. This means UAC is off, or the user is not an admin.
                    // In this case, we need to check if the user is actually an admin.
                    // We can fall back to CheckTokenMembership here, or assume non-elevated if UAC is on.
                    // If UAC is off, then default means full admin.
                    // The most reliable way to check if UAC is on is to check TokenElevation.
                    NativeMethods.GetTokenInformation(clientToken, NativeMethods.TOKEN_INFORMATION_CLASS.TokenElevation, IntPtr.Zero, 0, out returnLength);
                    pElevation = Marshal.AllocHGlobal((int)returnLength);
                    if (!NativeMethods.GetTokenInformation(clientToken, NativeMethods.TOKEN_INFORMATION_CLASS.TokenElevation, pElevation, returnLength, out returnLength))
                    {
                        Log($"IsClientAdmin: GetTokenInformation (TokenElevation) failed. LastWin32Error: {Marshal.GetLastWin32Error()}");
                        return false;
                    }
                    NativeMethods.TOKEN_ELEVATION elevation = (NativeMethods.TOKEN_ELEVATION)Marshal.PtrToStructure(pElevation, typeof(NativeMethods.TOKEN_ELEVATION))!;
                    if (elevation.TokenIsElevated != 0)
                    {
                        isElevated = true;
                    }
                    else
                    {
                        isElevated = false;
                    }
                }

                Log($"IsClientAdmin: Client is running with elevated administrator privileges: {isElevated}.");
                return isElevated;
            }
            catch (Exception ex)
            {
                Log($"ERROR: IsClientAdmin: Exception during elevated privilege check: {ex.Message}, LastWin32Error: {Marshal.GetLastWin32Error()}");
                return false;
            }
            finally
            {
                if (pElevationType != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(pElevationType);
                }
                if (pElevation != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(pElevation);
                }
            }
        }

        private IntPtr GetElevatedToken(IntPtr clientToken)
        {
            Log($"GetElevatedToken: Entered with clientToken: {clientToken}");
            uint returnLength;
            IntPtr linkedTokenPtr = IntPtr.Zero;
            try
            {
                Log("GetElevatedToken: Calling GetTokenInformation for TokenLinkedToken.");
                NativeMethods.GetTokenInformation(clientToken, NativeMethods.TOKEN_INFORMATION_CLASS.TokenLinkedToken, IntPtr.Zero, 0, out returnLength);
                if (returnLength > 0)
                {
                    linkedTokenPtr = Marshal.AllocHGlobal((int)returnLength);
                    Log($"GetElevatedToken: Allocated memory for linkedTokenPtr: {linkedTokenPtr}, returnLength: {returnLength}");
                    if (NativeMethods.GetTokenInformation(clientToken, NativeMethods.TOKEN_INFORMATION_CLASS.TokenLinkedToken, linkedTokenPtr, returnLength, out returnLength))
                    {
                        object obj = Marshal.PtrToStructure(linkedTokenPtr, typeof(NativeMethods.TOKEN_LINKED_TOKEN))!;
                        if (obj != null)
                        {
                            var linkedTokenStruct = (NativeMethods.TOKEN_LINKED_TOKEN)obj!;
                            if (linkedTokenStruct.LinkedToken != IntPtr.Zero)
                            {
                                Log($"GetElevatedToken: Successfully retrieved linked token: {linkedTokenStruct.LinkedToken}");
                                return linkedTokenStruct.LinkedToken;
                            }
                            else
                            {
                                Log("GetElevatedToken: LinkedToken is IntPtr.Zero.");
                            }
                        }
                        else
                        {
                            Log("GetElevatedToken: WARNING: Marshal.PtrToStructure returned null for TOKEN_LINKED_TOKEN.");
                        }
                    }
                    else
                    {
                        int lastError = Marshal.GetLastWin32Error();
                        Log($"GetElevatedToken: GetTokenInformation (TokenLinkedToken) failed. LastWin32Error: {lastError}");
                    }
                }
                else
                {
                    Log("GetElevatedToken: GetTokenInformation (TokenLinkedToken) returned 0 length.");
                }
            }
            finally
            {
                if (linkedTokenPtr != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(linkedTokenPtr);
                    Log($"GetElevatedToken: Freed linkedTokenPtr: {linkedTokenPtr}");
                }
            }
            Log("GetElevatedToken: Attempting DuplicateTokenEx as fallback.");
            IntPtr duplicatedToken = IntPtr.Zero;
            var sa = new NativeMethods.SECURITY_ATTRIBUTES();
            sa.nLength = Marshal.SizeOf(sa);
            sa.bInheritHandle = false;
            if (NativeMethods.DuplicateTokenEx(clientToken, NativeMethods.TokenAccessFlags.TOKEN_ALL_ACCESS, ref sa, NativeMethods.SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, NativeMethods.TOKEN_TYPE.TokenPrimary, out duplicatedToken))
            {
                Log($"GetElevatedToken: DuplicateTokenEx successful. Duplicated Token: {duplicatedToken}");
                return duplicatedToken;
            }
            else
            {
                int lastError = Marshal.GetLastWin32Error();
                Log($"GetElevatedToken: DuplicateTokenEx failed. LastWin32Error: {lastError}");
            }
            Log("GetElevatedToken: Returning IntPtr.Zero.");
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
    }
}
