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
        
                var options = new ProcessSpawnerOptions { WorkingDirectory = "C:\\", TargetSessionId = request.TargetSessionId };
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

            bool clientIsAdmin = IsClientAdmin(clientToken);
            Log($"GetSuTokenAsync: IsClientAdmin returned: {clientIsAdmin}");

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
                // check if it's a well-known non-interactive account.
                Log($"GetSuTokenAsync: Client is admin but target user is different. Checking for well-known non-interactive user.");

                string targetUserNameLower = request.TargetUser.ToLowerInvariant();
                if (targetUserNameLower == "system" || targetUserNameLower == "nt authority\\system" ||
                    targetUserNameLower == "network service" || targetUserNameLower == "nt authority\\network service" ||
                    targetUserNameLower == "local service" || targetUserNameLower == "nt authority\\local service")
                {
                    Log($"GetSuTokenAsync: Attempting to get token for well-known user: {request.TargetUser}");
                    IntPtr wellKnownUserToken = GetTokenForWellKnownUser(request.TargetUser);
                    if (wellKnownUserToken != IntPtr.Zero)
                    {
                        Log($"GetSuTokenAsync: Successfully obtained token for {request.TargetUser} without password.");
                        return wellKnownUserToken;
                    }
                    else
                    {
                        Log($"GetSuTokenAsync: Failed to get token for {request.TargetUser} without password. Falling back to password authentication.");
                    }
                }
                else
                {
                    Log($"GetSuTokenAsync: Target user {request.TargetUser} is not a well-known non-interactive user. Proceeding with password authentication.");
                }
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

        private IntPtr GetTokenForWellKnownUser(string targetUserName)
        {
            string normalizedTargetUser = targetUserName.ToLowerInvariant();

            // Case 1: Target is SYSTEM
            if (normalizedTargetUser == "system" || normalizedTargetUser == "nt authority\\system")
            {
                if (IsCurrentProcessSystem())
                {
                    Log("GetTokenForWellKnownUser: Current process is SYSTEM. Duplicating own token.");
                    IntPtr hCurrentProcessToken = IntPtr.Zero;
                    IntPtr duplicatedToken = IntPtr.Zero;

                    if (!NativeMethods.OpenProcessToken(NativeMethods.GetCurrentProcess(),
                                                        NativeMethods.TokenAccessFlags.TOKEN_DUPLICATE | NativeMethods.TokenAccessFlags.TOKEN_ASSIGN_PRIMARY | NativeMethods.TokenAccessFlags.TOKEN_QUERY,
                                                        out hCurrentProcessToken))
                    {
                        Log($"ERROR: GetTokenForWellKnownUser: OpenProcessToken for current process failed. LastWin32Error: {Marshal.GetLastWin32Error()}");
                        return IntPtr.Zero;
                    }

                    try
                    {
                        var sa = new NativeMethods.SECURITY_ATTRIBUTES();
                        sa.nLength = Marshal.SizeOf(sa);
                        sa.bInheritHandle = false;

                        if (NativeMethods.DuplicateTokenEx(hCurrentProcessToken,
                                                           NativeMethods.TokenAccessFlags.TOKEN_ALL_ACCESS,
                                                           ref sa,
                                                           NativeMethods.SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                                                           NativeMethods.TOKEN_TYPE.TokenPrimary,
                                                           out duplicatedToken))
                        {
                            Log($"GetTokenForWellKnownUser: Successfully duplicated current process token for SYSTEM.");
                            return duplicatedToken;
                        }
                        else
                        {
                            Log($"ERROR: GetTokenForWellKnownUser: DuplicateTokenEx for current process token failed. LastWin32Error: {Marshal.GetLastWin32Error()}");
                            return IntPtr.Zero;
                        }
                    }
                    finally
                    {
                        if (hCurrentProcessToken != IntPtr.Zero) NativeMethods.CloseHandle(hCurrentProcessToken);
                    }
                }
                else
                {
                    Log("GetTokenForWellKnownUser: Current process is not SYSTEM. Cannot directly get SYSTEM token without password.");
                    return IntPtr.Zero;
                }
            }
            // Case 2: Target is NETWORK SERVICE or LOCAL SERVICE
            else if (normalizedTargetUser == "network service" || normalizedTargetUser == "nt authority\\network service" ||
                     normalizedTargetUser == "local service" || normalizedTargetUser == "nt authority\\local service")
            {
                // Enable necessary privileges for LogonUser with service accounts
                if (!EnablePrivilege("SeAssignPrimaryTokenPrivilege") || !EnablePrivilege("SeIncreaseQuotaPrivilege"))
                {
                    Log($"GetTokenForWellKnownUser: Failed to enable required privileges for {targetUserName}.");
                    return IntPtr.Zero;
                }

                string username;
                string domain;

                int backslashIndex = targetUserName.IndexOf('\\');
                if (backslashIndex != -1)
                {
                    domain = targetUserName.Substring(0, backslashIndex);
                    username = targetUserName.Substring(backslashIndex + 1);
                }
                else
                {
                    username = targetUserName;
                    domain = "NT AUTHORITY"; // For well-known service accounts
                }

                Log($"GetTokenForWellKnownUser: Attempting LogonUser for service account: {username}, domain: {domain}");
                IntPtr hServiceToken = IntPtr.Zero;
                // Use LOGON32_LOGON_SERVICE for service accounts
                if (NativeMethods.LogonUserW(username, domain, null, NativeMethods.LogonType.LOGON32_LOGON_SERVICE, NativeMethods.LogonProvider.LOGON32_PROVIDER_DEFAULT, out hServiceToken))
                {
                    Log($"GetTokenForWellKnownUser: LogonUser successful for {targetUserName}. Token: {hServiceToken}");
                    return hServiceToken;
                }
                else
                {
                    Log($"ERROR: GetTokenForWellKnownUser: LogonUser failed for {targetUserName}. LastWin32Error: {Marshal.GetLastWin32Error()}");
                    return IntPtr.Zero;
                }
            }
            else
            {
                Log($"GetTokenForWellKnownUser: Target user {targetUserName} is not a recognized well-known non-interactive account for passwordless logon.");
                return IntPtr.Zero;
            }
        }

        private bool IsCurrentProcessSystem()
        {
            using (WindowsIdentity current = WindowsIdentity.GetCurrent())
            {
                return current.User?.IsWellKnown(WellKnownSidType.LocalSystemSid) == true;
            }
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

        private bool EnablePrivilege(string privilegeName)
        {
            IntPtr hToken = IntPtr.Zero;
            NativeMethods.LUID luid;

            if (!NativeMethods.OpenProcessToken(NativeMethods.GetCurrentProcess(),
                                                NativeMethods.TokenAccessFlags.TOKEN_ADJUST_PRIVILEGES | NativeMethods.TokenAccessFlags.TOKEN_QUERY,
                                                out hToken))
            {
                Log($"EnablePrivilege: OpenProcessToken failed. LastWin32Error: {Marshal.GetLastWin32Error()}");
                return false;
            }

            try
            {
                if (!NativeMethods.LookupPrivilegeValue(null, privilegeName, out luid))
                {
                    Log($"EnablePrivilege: LookupPrivilegeValue for {privilegeName} failed. LastWin32Error: {Marshal.GetLastWin32Error()}");
                    return false;
                }

                NativeMethods.TOKEN_PRIVILEGES tp = new NativeMethods.TOKEN_PRIVILEGES();
                tp.PrivilegeCount = 1;
                tp.Privileges = new NativeMethods.LUID_AND_ATTRIBUTES[1];
                tp.Privileges[0].Luid = luid;
                tp.Privileges[0].Attributes = NativeMethods.SE_PRIVILEGE_ENABLED;

                if (!NativeMethods.AdjustTokenPrivileges(hToken, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero))
                {
                    Log($"EnablePrivilege: AdjustTokenPrivileges for {privilegeName} failed. LastWin32Error: {Marshal.GetLastWin32Error()}");
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

    }
}
