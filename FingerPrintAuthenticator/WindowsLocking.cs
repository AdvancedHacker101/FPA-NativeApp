#define ProcLockDisable //Disable process protection
using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Security.Cryptography;

#if ProcLockDisable
#warning "Process security is disabled"
#endif

namespace FingerPrintAuthenticator
{
    /// <summary>
    /// Handle locking background tasks
    /// </summary>
    class WindowsLocking
    {
        /// <summary>
        /// QR Code Generator
        /// </summary>
        QRGenerator qrGenerator;
        /// <summary>
        /// Process Protection
        /// </summary>
        ProcessLocker locker;
        /// <summary>
        /// UI Locker
        /// </summary>
        LockUI ui;
        /// <summary>
        /// Previously protected Process ID
        /// </summary>
        private int previousProtectionPID = -1;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="qrCodeGenerator">QR Code Generator</param>
        /// <param name="server">Android Server Instance</param>
        /// <param name="previousLockerID">Previously protected PID</param>
        public WindowsLocking(QRGenerator qrCodeGenerator, AndroidServer server, int previousLockerID)
        {
            qrGenerator = qrCodeGenerator;
            locker = new ProcessLocker();
            previousProtectionPID = previousLockerID;

            server.LockStateChanged += new Action<AndroidServer.LockState>((state) => {

                if (state == AndroidServer.LockState.Failed) Form1.WriteLine("Lock or Unlock Failed");
                else if (state == AndroidServer.LockState.Locked)
                {
                    Form1.WriteLine("Locking System");
                    LockSystem();
                }
                else
                {
                    Form1.WriteLine("Unlocking system");
                    UnlockSystem();
                }
            });
        }

        /// <summary>
        /// Unlock the system
        /// </summary>
        private void UnlockSystem()
        {
            ui.CloseLockForm();
#if ProcLockDisable
            Form1.WriteLine("Process Protection Disable Supressed");
#else
            locker.StopProtection();
#endif
        }

        /// <summary>
        /// Lock the system
        /// </summary>
        private void LockSystem()
        {
#if ProcLockDisable
            Form1.WriteLine("Process Protection Enable Supressed");
#else
            LockProcess();
#endif
            qrGenerator.DismissIfOpen();
            ui = new LockUI();
            ui.StartLockForm();
            Bitmap unlockCode = qrGenerator.GenerateQRCode("win");
            ui.PushQRCode(unlockCode);
        }

        /// <summary>
        /// Start process protection
        /// </summary>
        private void LockProcess()
        {
            int myPid = Process.GetCurrentProcess().Id;

            if (previousProtectionPID == -1)
            {
                Process protectorProcess = new Process();
                ProcessStartInfo startInfo = new ProcessStartInfo
                {
                    FileName = System.Windows.Forms.Application.ExecutablePath,
                    Arguments = $"protect {myPid}"
                };
                protectorProcess.StartInfo = startInfo;
                protectorProcess.Start();
                locker.StartProtectProcess(protectorProcess.Id, $"protect {myPid}");
            }
            else locker.StartProtectProcess(previousProtectionPID, $"protect {myPid}");

        }

        /// <summary>
        /// Create a new window logon key
        /// </summary>
        /// <returns>The non-hashed key to send to the device</returns>
        internal static string RegisterLogon()
        {
            if (File.Exists("logon.hash")) return null;

            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                byte[] logonKey = new byte[32]; //32 bytes are 256 bits
                rng.GetBytes(logonKey);
                string strKey = Convert.ToBase64String(logonKey);
                string digestedKey = SessionCrypto.DigestMessage(strKey);
                File.WriteAllText("logon.hash", digestedKey);
                return strKey;
            }
        }

        /// <summary>
        /// Remove the windows logon key
        /// </summary>
        internal static void CancelRegistration()
        {
            File.Delete("logon.hash");
        }

        /// <summary>
        /// Check if the key sent by the device if correct
        /// </summary>
        /// <param name="logonKey">The key sent by the device</param>
        /// <returns>True if the keys match, otherwise false</returns>
        internal static bool IsLogonValid(string logonKey)
        {
            if (!File.Exists("logon.hash")) return false;
            string digestedKey = SessionCrypto.DigestMessage(logonKey);
            string validLogonHash = File.ReadAllText("logon.hash");
            return validLogonHash == digestedKey;
        }

        /// <summary>
        /// Check if the logon key is created
        /// </summary>
        /// <returns>True if the key exists, otherwise false</returns>
        public static bool CanLock()
        {
            return File.Exists("logon.hash");
        }
    }
}
