using System;
using System.IO;

namespace net.ninebroadcast.engineering.sudo
{
    /// <summary>
    /// Defines the contract for a class that can spawn a process as a specific user.
    /// </summary>
    public interface ISudoProcessSpawner
    {
        /// <summary>
        /// Spawns a new process as the user represented by the token, with its I/O redirected to anonymous pipes.
        /// </summary>
        /// <param name="userToken">The primary token of the user to start the process as.</param>
        /// <param name="command">The command line to execute.</param>
        /// <param name="options">Options for the process creation.</param>
        /// <returns>A SudoProcess object containing the running process and the parent-side anonymous pipe streams.</returns>
        SudoProcess Spawn(IntPtr userToken, string command, ProcessSpawnerOptions options);
    }

    /// <summary>
    /// Holds options for spawning a new process.
    /// </summary>
    public class ProcessSpawnerOptions
    {
        public string WorkingDirectory { get; set; } = "C:\\";
        public uint? TargetSessionId { get; set; }
    }
}
