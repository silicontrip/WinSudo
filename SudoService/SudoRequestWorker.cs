using System;
using System.IO;
using System.IO.Pipes;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

namespace net.ninebroadcast.engineering.sudo
{
    public class SudoRequestWorker
    {
        private readonly NamedPipeServerStream _commandPipe;
        private readonly JsonSerializerOptions _jsonOptions;
        private readonly ISudoProcessSpawner _processSpawner;

        public SudoRequestWorker(NamedPipeServerStream commandPipe)
        {
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
                clientToken = GetClientToken();
                var request = await JsonSerializer.DeserializeAsync<SudoRequest>(_commandPipe, _jsonOptions);
                if (request == null)
                {
                    await SendErrorResponse("error", "Received empty or invalid request from client.");
                    return;
                }
        
                if (request.Mode.Equals("sudo", StringComparison.OrdinalIgnoreCase))
                {
                    userToken = await GetSudoTokenAsync(clientToken, request);
                }
                else if (request.Mode.Equals("su", StringComparison.OrdinalIgnoreCase))
                {
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
                await JsonSerializer.SerializeAsync(_commandPipe, successResponse, _jsonOptions);
                _commandPipe.WaitForPipeDrain();
        
                // The command pipe's job is done. Close it.
                _commandPipe.Close();
                _commandPipe.Dispose();
        
                // The SudoProcess object is now responsible for managing its internal pipes and I/O forwarding.
                // We just need to wait for the helper process to complete its work.
                await Task.Run(() => sudoProcess.Process.WaitForExit());
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"ERROR handling request: {ex.Message}");
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
            if (!IsClientAdmin(clientToken)) { await SendErrorResponse("access_denied", "User is not an administrator."); return IntPtr.Zero; }
            var challengeResponse = new SudoServerResponse { Status = "authentication_required" };
            await JsonSerializer.SerializeAsync(_commandPipe, challengeResponse, _jsonOptions);
            _commandPipe.WaitForPipeDrain();
            var authRequest = await JsonSerializer.DeserializeAsync<SudoRequest>(_commandPipe, _jsonOptions);
            if (authRequest == null)
            {
                await SendErrorResponse("error", "Received empty or invalid authentication request.");
                return IntPtr.Zero;
            }
            if (authRequest.Password == null)
            {
                await SendErrorResponse("authentication_failure", "Password not provided.");
                return IntPtr.Zero;
            }
            if (!ValidateUserPassword(clientToken, authRequest.Password)) { await SendErrorResponse("authentication_failure", "Invalid password."); return IntPtr.Zero; }
            return GetElevatedToken(clientToken);
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

        private bool ValidateUserPassword(IntPtr clientToken, string password)
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
                    NativeMethods.CloseHandle(hToken);
                    return true;
                }
                return false;
            }
            finally
            {
                if (pUser != IntPtr.Zero) Marshal.FreeHGlobal(pUser);
            }
        }

        private IntPtr GetElevatedToken(IntPtr clientToken)
        {
            uint returnLength;
            IntPtr linkedTokenPtr = IntPtr.Zero;
            try
            {
                NativeMethods.GetTokenInformation(clientToken, NativeMethods.TOKEN_INFORMATION_CLASS.TokenLinkedToken, IntPtr.Zero, 0, out returnLength);
                if (returnLength > 0)
                {
                    linkedTokenPtr = Marshal.AllocHGlobal((int)returnLength);
                    if (NativeMethods.GetTokenInformation(clientToken, NativeMethods.TOKEN_INFORMATION_CLASS.TokenLinkedToken, linkedTokenPtr, returnLength, out returnLength))
                    {
                        object obj = Marshal.PtrToStructure(linkedTokenPtr, typeof(NativeMethods.TOKEN_LINKED_TOKEN))!;
                        if (obj != null)
                        {
                            var linkedTokenStruct = (NativeMethods.TOKEN_LINKED_TOKEN)obj!;
                            if (linkedTokenStruct.LinkedToken != IntPtr.Zero) return linkedTokenStruct.LinkedToken;
                        }
                        else
                        {
                            System.Diagnostics.Debug.WriteLine("WARNING: Marshal.PtrToStructure returned null for TOKEN_LINKED_TOKEN.");
                        }
                    }
                }
            }
            finally
            {
                if (linkedTokenPtr != IntPtr.Zero) Marshal.FreeHGlobal(linkedTokenPtr);
            }
            IntPtr duplicatedToken = IntPtr.Zero;
            var sa = new NativeMethods.SECURITY_ATTRIBUTES();
            sa.nLength = Marshal.SizeOf(sa);
            sa.bInheritHandle = false;
            if (NativeMethods.DuplicateTokenEx(clientToken, NativeMethods.TokenAccessFlags.TOKEN_ALL_ACCESS, ref sa, NativeMethods.SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, NativeMethods.TOKEN_TYPE.TokenPrimary, out duplicatedToken)) return duplicatedToken;
            return IntPtr.Zero;
        }

        private async Task SendErrorResponse(string status, string message)
        {
            var errorResponse = new SudoServerResponse { Status = status, ErrorMessage = message };
            await JsonSerializer.SerializeAsync(_commandPipe, errorResponse, _jsonOptions);
            _commandPipe.WaitForPipeDrain();
        }
    }
}
