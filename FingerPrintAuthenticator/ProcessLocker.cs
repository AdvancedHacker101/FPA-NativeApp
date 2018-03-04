using System;
using System.Diagnostics;

namespace FingerPrintAuthenticator
{
    /// <summary>
    /// Process stop protection class
    /// </summary>
    class ProcessLocker
    {
        /// <summary>
        /// Determines if a process is currently protected
        /// </summary>
        private bool isProtecting = false;
        /// <summary>
        /// The process to protect
        /// </summary>
        Process toProtect;

        /// <summary>
        /// Start protecting a process
        /// </summary>
        /// <param name="pid">Process ID of the Process to protect</param>
        /// <param name="restartArgs">The arguments to give to the process when restarting</param>
        public void StartProtectProcess(int pid, string restartArgs)
        {
            isProtecting = true;
            Process p = Process.GetProcessById(pid);
            toProtect = p;
            p.EnableRaisingEvents = true;
            p.Exited += new EventHandler((sender, e) => {
                ProcessClosed(sender, e, restartArgs, System.Windows.Forms.Application.ExecutablePath);
            });
        }

        /// <summary>
        /// Stop protecting the currently protected process
        /// </summary>
        public void StopProtection()
        {
            isProtecting = false;
            toProtect.Kill();
            toProtect.Dispose();
            toProtect = null;
        }

        /// <summary>
        /// Event callback if the protected process is closed
        /// </summary>
        /// <param name="sender">The sender of the event</param>
        /// <param name="e">The event args</param>
        /// <param name="restartArgs">The restart arguments</param>
        /// <param name="restartPath">The process to restart</param>
        private void ProcessClosed(object sender, EventArgs e, string restartArgs, string restartPath)
        {
            if (!isProtecting) return;
            Process p = new Process();
            ProcessStartInfo info = new ProcessStartInfo
            {
                FileName = restartPath,
                Arguments = restartArgs
            };

            p.StartInfo = info;
            p.EnableRaisingEvents = true;
            p.Start();
            StartProtectProcess(p.Id, restartArgs);
        }
    }
}
