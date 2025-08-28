using System;
using System.IO;

namespace net.ninebroadcast.engineering.sudo
{
    public static class Logger
    {
        private static readonly string LogFilePath;
        private static readonly object Lock = new object();

        static Logger()
        {
            string programDataPath = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            string logDirectory = Path.Combine(programDataPath, "SudoService", "Logs");
            Directory.CreateDirectory(logDirectory); // Ensure the directory exists
            LogFilePath = Path.Combine(logDirectory, "SudoService.log");
        }

        public static void Log(string message)
        {
            try
            {
                lock (Lock)
                {
                    File.AppendAllText(LogFilePath, $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}] {message}{Environment.NewLine}");
                }
            }
            catch (Exception ex)
            {
                // Fallback for logging errors, e.g., to console or event log if possible
                System.Diagnostics.Debug.WriteLine($"ERROR: Failed to write to log file: {ex.Message}");
            }
        }
    }
}