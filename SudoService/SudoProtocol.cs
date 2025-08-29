using System;

namespace net.ninebroadcast.engineering.sudo
{
    /// <summary>
    /// Represents a request from the client to the server.
    /// Contains all possible fields for any request type.
    /// </summary>
    public class SudoRequest
    {
        public string Mode { get; set; } = "";
        public string Command { get; set; } = "";
        public string? TargetUser { get; set; }
        public string? Password { get; set; } // Can be used for the auth challenge response
        public string SpawnerType { get; set; } = "pipe";
        public uint? SessionId { get; set; }
    }

    /// <summary>
    /// Represents a response from the server to the client.
    /// Contains all possible fields for any response type.
    /// </summary>
    public class SudoServerResponse
    {
        public string Status { get; set; } = "";
        public string? ErrorMessage { get; set; }
        public string? StdinPipeName { get; set; }
        public string? StdoutPipeName { get; set; }
        public string? StderrPipeName { get; set; }
    }
}