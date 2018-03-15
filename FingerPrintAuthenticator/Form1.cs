using System;
using System.Drawing;
using System.Net;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace FingerPrintAuthenticator
{
    /// <summary>
    /// Main Entry Class
    /// </summary>
    public partial class Form1 : Form
    {
        /// <summary>
        /// Notification of process running in the background
        /// </summary>
        private NotifyIcon backgroundIcon;
        /// <summary>
        /// Android Communication Server
        /// </summary>
        private AndroidServer androidServer;
        /// <summary>
        /// RSA Key Pair generator
        /// </summary>
        private KeyGeneration keyGeneration;
        /// <summary>
        /// QR Code Generator
        /// </summary>
        private QRGenerator qrCodeGenerator;
        /// <summary>
        /// System Locking Object
        /// </summary>
        private WindowsLocking systemLocking;
        /// <summary>
        /// Static Reference to the form
        /// </summary>
        public static Form1 me;
        /// <summary>
        /// Debug output control
        /// </summary>
        private static RichTextBox debugWindow;
        /// <summary>
        /// Javascript Communication Server
        /// </summary>
        private JavascriptServer javascriptServer;

        /// <summary>
        /// Constructor
        /// </summary>
        public Form1()
        {
            InitializeComponent();
            me = this;
        }

        /// <summary>
        /// Build notification context menu strip
        /// </summary>
        /// <returns>Context menu strip for the notification to set</returns>
        private ContextMenuStrip GetContextMenu()
        {
            ContextMenuStrip cms = new ContextMenuStrip();
            cms.Items.Add("Lock", null, new EventHandler(ApplicationLock));
            cms.Items.Add("Exit", null, new EventHandler(ApplicationExit));
            return cms;
        }

        /// <summary>
        /// Application exit point
        /// </summary>
        /// <param name="sender">Sender</param>
        /// <param name="e">EventArgs</param>
        private void ApplicationExit(object sender, EventArgs e)
        {
            if (MessageBox.Show(this, "Do you really want to exit?\r\nThis will prevent you from using the browser authentication!", "Are you sure?", MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes)
            {
                //Cleanup code here
                androidServer.CloseServer();
                javascriptServer.CloseServer();
                backgroundIcon.Visible = false;
                backgroundIcon.Dispose();
                Environment.Exit(0);
            }
        }

        /// <summary>
        /// Application Lock Context Menu Option
        /// </summary>
        /// <param name="sender">Sender</param>
        /// <param name="e">EventArgs</param>
        private void ApplicationLock(object sender, EventArgs e)
        {
            Bitmap code = qrCodeGenerator.GenerateQRCode("lock");
            qrCodeGenerator.DismissIfOpen();
            qrCodeGenerator.DisplayQRCode(code, "Scan the QR Code to Lock PC");
        }

        /// <summary>
        /// Hide form and create notification
        /// </summary>
        private void LoadToTraybar()
        {
            Hide();
            NotifyIcon icon = new NotifyIcon
            {
                Visible = true,
                BalloonTipTitle = "Entering Backgournd Mode",
                BalloonTipText = "The application enters into background mode, for browser authentication.",
                Text = "Fingerprint Authentication",
                ContextMenuStrip = GetContextMenu(),
                Icon = SystemIcons.Application,
            };

            backgroundIcon = icon;
            icon.ShowBalloonTip(500);
        }

        /// <summary>
        /// Load RSA Key pair generator
        /// </summary>
        private void LoadKeyGeneration()
        {
            keyGeneration = new KeyGeneration();
            keyGeneration.GenerateKeys();
        }

        /// <summary>
        /// Create new android communication server
        /// </summary>
        private void LoadAndroidServer()
        {
            IPEndPoint ep = new IPEndPoint(IPAddress.Any, 9624);
            androidServer = new AndroidServer(ep, keyGeneration);
            androidServer.DismissIfOpen += new Action(DismissIfOpen);
        }

        /// <summary>
        /// Load debugging output window
        /// </summary>
        private void LoadDebugWindow()
        {
            Form f = new Form
            {
                Size = new Size(900, 600),
                FormBorderStyle = FormBorderStyle.FixedToolWindow
            };
            RichTextBox rtb = new RichTextBox
            {
                Dock = DockStyle.Fill,
                ForeColor = Color.Cyan,
                BackColor = Color.Black
            };
            f.Controls.Add(rtb);
            f.Show();
            debugWindow = rtb;
        }

        /// <summary>
        /// Write line to debug window
        /// </summary>
        /// <param name="text">The text to output</param>
        public static void WriteLine(string text)
        {
            if (debugWindow == null) return;

            Action<string> appendText = new Action<string>((textToAppend) => {
                debugWindow.AppendText(textToAppend + Environment.NewLine);
            });

            if (me.InvokeRequired) me.Invoke(appendText, new object[] { text });
            else appendText(text);
        }

        /// <summary>
        /// Create new javascript communication server
        /// </summary>
        private void LoadJavascriptServer()
        {
            javascriptServer = new JavascriptServer(this);
            javascriptServer.StartServer();
            androidServer.SetJavascriptServer(javascriptServer);
        }

        /// <summary>
        /// Display a QR Code requsting to store a password on the android device
        /// </summary>
        /// <param name="url">The plain text url to store</param>
        internal void RequestPasswordStore(string url)
        {
            Action displayQRCode = new Action(() => {
                string hashName = SessionCrypto.DigestMessage(url);
                Bitmap qrCode = qrCodeGenerator.GenerateQRCode($"storpw-{hashName}");
                qrCodeGenerator.DismissIfOpen();
                qrCodeGenerator.DisplayQRCode(qrCode, "Scan QR Code to store website credentials");
                qrCodeGenerator.PushToTop();
            });

            if (InvokeRequired) Invoke(displayQRCode);
            else displayQRCode();
        }

        /// <summary>
        /// Display a QR Code requesting to get a password from the android device
        /// </summary>
        /// <param name="urlHash">The hashed url to get the credentials of</param>
        internal void RequestPasswordGet(string urlHash)
        {
            Action displayQRCode = new Action(() => {
                Bitmap qrCode = qrCodeGenerator.GenerateQRCode($"pw-{urlHash}");
                qrCodeGenerator.DismissIfOpen();
                qrCodeGenerator.DisplayQRCode(qrCode, "Scan QR Code to get website credentials");
                qrCodeGenerator.PushToTop();
            });

            if (InvokeRequired) Invoke(displayQRCode);
            else displayQRCode();
        }

        internal void RequestKeyGet(string urlHash)
        {
            Action displayQRCode = new Action(() => {
                Bitmap qrCode = qrCodeGenerator.GenerateQRCode($"getkvalue-{urlHash}");
                qrCodeGenerator.DismissIfOpen();
                qrCodeGenerator.DisplayQRCode(qrCode, "Scan QR Code to get website credentials");
                qrCodeGenerator.PushToTop();
            });

            if (InvokeRequired) Invoke(displayQRCode);
            else displayQRCode();
        }

        internal void RequestKeyStore(string urlHash)
        {
            Action displayQRCode = new Action(() => {
                Bitmap qrCode = qrCodeGenerator.GenerateQRCode($"getkname-{urlHash}");
                qrCodeGenerator.DismissIfOpen();
                qrCodeGenerator.DisplayQRCode(qrCode, "Scan QR Code to get website credentials");
                qrCodeGenerator.PushToTop();
            });

            if (InvokeRequired) Invoke(displayQRCode);
            else displayQRCode();
        }

        private void ConfirgureRegistryStart()
        {
            if (!WindowsLocking.CanLock()) return;
            const string startupLocation = "hkcu\\Software\\Microsoft\\Windows\\CurrentVersion\\Run";
            const string valueName = "fpalock";
            string appLocation = $"{Application.ExecutablePath} forcelock";
            if (!RegistryHelper.ValueExists(startupLocation, valueName))
            {
                RegistryHelper.AddValue(startupLocation, valueName, appLocation);
            }
        }

        /// <summary>
        /// QR Code Display Dismiss Event Handler
        /// </summary>
        public void DismissIfOpen()
        {
            qrCodeGenerator.DismissIfOpen();
        }

        /// <summary>
        /// Form Shown Event Handler
        /// </summary>
        /// <param name="sender">Sender</param>
        /// <param name="e">EventArgs</param>
        private void Form1_Shown(object sender, EventArgs e)
        {
            string[] arguments = Environment.GetCommandLineArgs();
            int protectPid = -1;
            if (arguments.Length == 3 && arguments[1] == "protect") protectPid = (int.TryParse(arguments[2], out int result)) ? result : -1;

            if (protectPid == -1)
            {
#if DEBUG
                LoadDebugWindow();
#endif
                //LoadToTraybar();
                qrCodeGenerator = new QRGenerator();
                qrCodeGenerator.SetData(AndroidServer.GetLocalIPAddress(), 9624);
                LoadKeyGeneration();
                LoadAndroidServer();
                LoadJavascriptServer();
                int protectorPID = -1;
                if (arguments.Length == 3 && arguments[1] == "lock")
                {
                    protectorPID = (int.TryParse(arguments[2], out int result)) ? result : -1;
                    if (!WindowsLocking.CanLock()) protectorPID = -1;
                }

                systemLocking = new WindowsLocking(qrCodeGenerator, androidServer, protectorPID);
                if (protectorPID != -1) androidServer.SendLockSignal();
                if (arguments.Length == 2 && arguments[2] == "forcelock" && WindowsLocking.CanLock()) androidServer.SendLockSignal();
            }
            else
            {
                Hide();
                ProcessLocker locker = new ProcessLocker();
                locker.StartProtectProcess(protectPid, $"lock {System.Diagnostics.Process.GetCurrentProcess().Id}");
            }
        }

        /// <summary>
        /// Test lock
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void button1_Click(object sender, EventArgs e)
        {
            Bitmap code = qrCodeGenerator.GenerateQRCode("lock");
            qrCodeGenerator.DismissIfOpen();
            qrCodeGenerator.DisplayQRCode(code, "Scan the QR code to lock the PC");
        }

        /// <summary>
        /// Register locking
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void button2_Click(object sender, EventArgs e)
        {
            Bitmap qrCode = qrCodeGenerator.GenerateQRCode("getkname-windowsLogon");
            qrCodeGenerator.DismissIfOpen();
            qrCodeGenerator.DisplayQRCode(qrCode, "Scan the QR Code to Register PC Locking");
        }

        /// <summary>
        /// Force Lock Form
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void button3_Click(object sender, EventArgs e)
        {
            androidServer.SendLockSignal();
        }

        /// <summary>
        /// Test BringToFront
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void button4_Click(object sender, EventArgs e)
        {
            TopMost = true;

            Task.Factory.StartNew(() =>
            {
                while (true)
                {
                    System.Threading.Thread.Sleep(3000);
                    Action topMost = new Action(() =>
                    {
                        
                        BringToFront();
                        WindowState = FormWindowState.Normal;
                    });
                    if (InvokeRequired) Invoke(topMost);
                    else topMost();
                }
            });

        }

        private void button5_Click(object sender, EventArgs e)
        {
            const string webSiteName = "www.facebook.com/login";
            string hashName = SessionCrypto.DigestMessage(webSiteName);
            Bitmap qrCode = qrCodeGenerator.GenerateQRCode($"pw-{hashName}");
            qrCodeGenerator.DismissIfOpen();
            qrCodeGenerator.DisplayQRCode(qrCode, "Scan QR Code to fill website credentials");
        }

        private void button6_Click(object sender, EventArgs e)
        {
            const string webSiteName = "www.facebook.com/login";
            string hashName = SessionCrypto.DigestMessage(webSiteName);
            Bitmap qrCode = qrCodeGenerator.GenerateQRCode($"storpw-{hashName}");
            qrCodeGenerator.DismissIfOpen();
            qrCodeGenerator.DisplayQRCode(qrCode, "Scan QR Code to store website credentials");
        }
    }
}