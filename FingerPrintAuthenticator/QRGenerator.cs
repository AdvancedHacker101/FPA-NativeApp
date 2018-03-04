using QRCoder;
using System;
using System.Drawing;
using System.Windows.Forms;

namespace FingerPrintAuthenticator
{
    /// <summary>
    /// QR Code Generator Class
    /// </summary>
    class QRGenerator
    {
        /// <summary>
        /// The IP the server is running on
        /// </summary>
        private string selfIP;
        /// <summary>
        /// The port the server is running on
        /// </summary>
        private int selfPort;
        /// <summary>
        /// The form which displays the QR Code
        /// </summary>
        private Form displayWindowReference;

        /// <summary>
        /// Set the server information
        /// </summary>
        /// <param name="ip">IP Address of the server</param>
        /// <param name="port">Port number of the server</param>
        public void SetData(string ip, int port)
        {
            selfIP = ip;
            selfPort = port;
        }

        /// <summary>
        /// Generate a QR Code with the requested resource encoded
        /// </summary>
        /// <param name="requestedResource">The resource the server wants to access</param>
        /// <returns>QR Code containing the needed information</returns>
        public Bitmap GenerateQRCode(string requestedResource)
        {
            QRCodeGenerator qrGenerator = new QRCodeGenerator();
            string data = $"{selfIP}:{selfPort}-{requestedResource}";
            QRCodeData qrCodeData = qrGenerator.CreateQrCode(data, QRCodeGenerator.ECCLevel.Q);
            QRCode qrCode = new QRCode(qrCodeData);
            return qrCode.GetGraphic(20);
        }

        /// <summary>
        /// Open a new window and display a QR Code
        /// </summary>
        /// <param name="qrCode">The QR Code to display</param>
        /// <param name="message">The title of the form</param>
        public void DisplayQRCode(Bitmap qrCode, string message)
        {
            if (displayWindowReference != null) throw new InvalidOperationException("Error, previous QR Code from is not closed");
            Form f = new Form
            {
                Text = message,
                StartPosition = FormStartPosition.CenterScreen
            };
            PictureBox pb = new PictureBox
            {
                Image = qrCode,
                SizeMode = PictureBoxSizeMode.AutoSize,
                Location = new Point(0, 0)
            };
            f.Controls.Add(pb);
            f.Size = pb.Size;
            f.Show();
            displayWindowReference = f;
        }

        /// <summary>
        /// Push The QR Code display window above all other windows
        /// </summary>
        public void PushToTop()
        {
            if (displayWindowReference == null) throw new NullReferenceException("Error, QR Code display window isn't initialized");
            Action bringToFront = new Action(() => {
                displayWindowReference.TopMost = true;
                displayWindowReference.BringToFront();
                displayWindowReference.TopMost = false;
            });

            if (Form1.me.InvokeRequired) displayWindowReference.Invoke(bringToFront);
            else bringToFront();
        }

        /// <summary>
        /// Close the QR Code display window
        /// </summary>
        public void DismissIfOpen()
        {
            if (displayWindowReference != null)
            {
                Action closeWindow = new Action(() => {
                    displayWindowReference.Close();
                    displayWindowReference.Dispose();
                    displayWindowReference = null;
                });

                if (displayWindowReference.InvokeRequired) displayWindowReference.Invoke(closeWindow);
                else closeWindow();
            }
        }
    }
}
