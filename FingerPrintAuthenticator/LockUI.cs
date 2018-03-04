#define SafetyButton //Add a safety button to the LockForm to close the form if it locks up
#define ForceTopDisable //Disable the BringToFront loop for debugging purposes

using System;
using System.Collections.Generic;
using System.Drawing;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

#if SafetyButton
#warning Lock screen can be bypassed!
#endif

#if ForceTopDisable
#warning Window forcing top protection disabled
#endif

namespace FingerPrintAuthenticator
{
    /// <summary>
    /// UI handler for the system lock
    /// </summary>
    class LockUI
    {
        /// <summary>
        /// The pictureBox which can store QR Codes
        /// </summary>
        private PictureBox qrCodePlaceholder;
        /// <summary>
        /// The main lock from with the QR Code
        /// </summary>
        private Form lockForm;
        /// <summary>
        /// Token source to cancel the BringToFront loop
        /// </summary>
        private CancellationTokenSource protectionCancel;
        /// <summary>
        /// A list of forms used to lock other monitor than the main monitor
        /// </summary>
        private List<Form> screenBlockers = new List<Form>();

        /// <summary>
        /// Start the Locking UI
        /// </summary>
        internal void StartLockForm()
        {
            lockForm = new Form
            {
                FormBorderStyle = FormBorderStyle.None,
                WindowState = FormWindowState.Normal,
                Text = "FP Auth Lock Window",
                StartPosition = FormStartPosition.Manual,
                BackColor = Color.White
            };
            qrCodePlaceholder = new PictureBox
            {
                SizeMode = PictureBoxSizeMode.AutoSize,
            };

            lockForm.Controls.Add(qrCodePlaceholder);
#if SafetyButton
            AddSafetyButton(lockForm);
#endif
#if ForceTopDisable
            Form1.WriteLine("Foreground Protection Enable Supressed");
#else
            protectionCancel = new CancellationTokenSource();
            StartForegroundProtection(lockForm);
#endif
            Screen primary = Screen.PrimaryScreen;
            lockForm.SetBounds(primary.Bounds.X, primary.Bounds.Y, primary.Bounds.Width, primary.Bounds.Height);
            Action showForm = new Action(() => lockForm.Show());
            if (Form1.me.InvokeRequired) Form1.me.Invoke(showForm);
            else showForm();

            screenBlockers.Clear();

            foreach (Screen desktop in Screen.AllScreens)
            {
                if (desktop == primary) continue;
                Form screenLocker = new Form
                {
                    StartPosition = FormStartPosition.Manual,
                    FormBorderStyle = FormBorderStyle.None,
                    BackColor = Color.White
                };
                screenLocker.SetBounds(desktop.Bounds.X, desktop.Bounds.Y, desktop.Bounds.Width, desktop.Bounds.Height);
                Label l = new Label
                {
                    Text = "Computer Is Locked, and this screen is blocked from using it, until not logged in",
                    AutoSize = false,
                    TextAlign = ContentAlignment.MiddleCenter,
                    Dock = DockStyle.Fill
                };

                Font f = new Font(FontFamily.GenericSansSerif, 12);
                l.Font = f;

                screenLocker.Controls.Add(l);
                Action showBlocker = new Action(() => screenLocker.Show());
                if (Form1.me.InvokeRequired) Form1.me.Invoke(showBlocker);
                else showBlocker();

#if ForceTopDisable
                Form1.WriteLine("Foreground Protection Enable Supressed");
#else
                StartForegroundProtection(screenLocker);
#endif

                screenBlockers.Add(screenLocker);
            }
        }

        /// <summary>
        /// Add the safety bypass button to the form
        /// </summary>
        /// <param name="f">The form to add the button to</param>
        private void AddSafetyButton(Form f)
        {
            Button cancelButton = new Button
            {
                Text = "Bypass login",
                UseVisualStyleBackColor = true
            };
            cancelButton.Click += new EventHandler((sender, e) => { CloseLockForm(); });
            f.Controls.Add(cancelButton);
        }

        /// <summary>
        /// Start the BringToFront loop
        /// </summary>
        /// <param name="formToProtect">The form to start the loop on</param>
        private void StartForegroundProtection(Form formToProtect)
        {
            CancellationToken ct = protectionCancel.Token;
            formToProtect.TopMost = true;

            Task t = Task.Factory.StartNew(() => {
                Action blockScreen = new Action(() =>
                {
                    formToProtect.BringToFront();
                    if (formToProtect.WindowState != FormWindowState.Normal) formToProtect.WindowState = FormWindowState.Normal;
                });

                while (!ct.IsCancellationRequested)
                {
                    if (formToProtect.InvokeRequired) formToProtect.Invoke(blockScreen);
                    else blockScreen();
                    Thread.Sleep(100);
                }
            }, ct);
        }

        /// <summary>
        /// Stop all BringToFront loops
        /// </summary>
        private void StopForegroundProtection()
        {
            protectionCancel.Cancel();
        }

        /// <summary>
        /// Close the locking UI
        /// </summary>
        internal void CloseLockForm()
        {
#if ForceTopDisable
            Form1.WriteLine("Foreground protection disable supressed");
#else
            StopForegroundProtection();
#endif
            Action removeForm = new Action(() => {
                lockForm.Close();
                lockForm.Dispose();
            });

            if (Form1.me.InvokeRequired) Form1.me.Invoke(removeForm);
            else removeForm();

            foreach (Form blocker in screenBlockers)
            {
                Action removeBlocker = new Action(()=> {
                    blocker.Close();
                    blocker.Dispose();
                });

                if (Form1.me.InvokeRequired) Form1.me.Invoke(removeBlocker);
                else removeBlocker();
            }
        }

        /// <summary>
        /// Display a QR Code on the main UI
        /// </summary>
        /// <param name="image"></param>
        internal void PushQRCode(Bitmap image)
        {
            Action updateQRCode = new Action(() =>
            {
                qrCodePlaceholder.Image = image;
                Point qrCodePosition = new Point(
                    lockForm.Width / 2 - qrCodePlaceholder.Width / 2,
                    lockForm.Height / 2 - qrCodePlaceholder.Height / 2
                    );

                qrCodePlaceholder.Location = qrCodePosition;
            });
            if (lockForm.InvokeRequired) lockForm.Invoke(updateQRCode);
            else updateQRCode();
        }
    }
}
