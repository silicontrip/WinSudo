
using System;
using System.ServiceProcess;

namespace net.ninebroadcast.engineering.sudo
{
    public class Program
    {
        /// <summary>
        /// The main entry point for the application.
        /// </summary>
        public static void Main(string[] args)
        {
            // If we are running in an interactive console, run the service as a console app.
            // This makes debugging much easier than attaching to a running service.
            if (Environment.UserInteractive)
            {
                var sudoService = new SudoService();
                sudoService.RunAsConsole(args);
            }
            else
            {
                // Otherwise, run it as a standard Windows Service.
                ServiceBase.Run(new SudoService());
            }
        }
    }
}
