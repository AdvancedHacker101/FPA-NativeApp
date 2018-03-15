using System;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace FingerPrintAuthenticator
{
    /// <summary>
    /// Server for android devices
    /// </summary>
    class AndroidServer
    {
        /// <summary>
        /// System Locking state
        /// </summary>
        public enum LockState
        {
            /// <summary>
            /// Lock the system
            /// </summary>
            Locked,
            /// <summary>
            /// Unlock the system
            /// </summary>
            Unlocked,
            /// <summary>
            /// Lock or Unlock Failed
            /// </summary>
            Failed
        }

        /// <summary>
        /// Event for new connections
        /// </summary>
        public event Action<IPEndPoint> DeviceConnected;
        /// <summary>
        /// Event for server errors
        /// </summary>
        public event Action<Exception> ServerError;
        /// <summary>
        /// Event for system locking
        /// </summary>
        public event Action<LockState> LockStateChanged;
        /// <summary>
        /// The server socket
        /// </summary>
        private Socket serverSocket;
        /// <summary>
        /// RSA key pair generator
        /// </summary>
        private KeyGeneration keyGeneration;
        /// <summary>
        /// Javascript server instance
        /// </summary>
        private JavascriptServer jsSrv;
        /// <summary>
        /// QR Code dismiss callback event
        /// </summary>
        public event Action DismissIfOpen;

        /// <summary>
        /// Connection data
        /// </summary>
        private struct ReadObject
        {
            /// <summary>
            /// Android Client Socket
            /// </summary>
            public Socket client;
            /// <summary>
            /// Receive buffer
            /// </summary>
            public byte[] buffer;
            /// <summary>
            /// Determines if this message is the first
            /// </summary>
            public bool isFirstMessage;
            /// <summary>
            /// Session crypto object
            /// </summary>
            public SessionCrypto session;
            /// <summary>
            /// The requested resource
            /// </summary>
            public string requestString;
            /// <summary>
            /// Sent Credentials
            /// </summary>
            public Credentials credentials;
            /// <summary>
            /// Key to send to the device
            /// </summary>
            public string pushKey;
        }

        /// <summary>
        /// Website credentials
        /// </summary>
        private struct Credentials
        {
            /// <summary>
            /// Username
            /// </summary>
            public string username;
            /// <summary>
            /// Password
            /// </summary>
            public string password;
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="serverEndPoint">EndPoint to bind to</param>
        /// <param name="keyGenerator">Key generator object</param>
        public AndroidServer(IPEndPoint serverEndPoint, KeyGeneration keyGenerator)
        {
            keyGeneration = keyGenerator;
            serverSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            serverSocket.Bind(serverEndPoint);
            serverSocket.Listen(1);

            serverSocket.BeginAccept(new AsyncCallback(AcceptCallback), null);
        }

        /// <summary>
        /// Set the Javascript server instance of the server
        /// </summary>
        /// <param name="jsServer">The javascript server</param>
        public void SetJavascriptServer(JavascriptServer jsServer)
        {
            jsSrv = jsServer;
        }

        /// <summary>
        /// Get the local IPv4 address of the machine
        /// </summary>
        /// <returns>The local IPv4 Address of the machine, null if failed</returns>
        public static string GetLocalIPAddress()
        {
            IPHostEntry host = Dns.GetHostEntry(Dns.GetHostName());
            foreach (var ip in host.AddressList)
            {
                if (ip.AddressFamily == AddressFamily.InterNetwork)
                {
                    return ip.ToString();
                }
            }
            throw new Exception("No network adapters with an IPv4 address in the system!");
        }

        /// <summary>
        /// Shutdown the android server
        /// </summary>
        public void CloseServer()
        {
            try
            {
                serverSocket.Close();
                serverSocket.Dispose();
                serverSocket = null;
            }
            catch (Exception ex)
            {
                ServerError?.Invoke(ex);
                return;
            }
        }

        /// <summary>
        /// Force lock the system
        /// </summary>
        internal void SendLockSignal()
        {
            LockStateChanged?.Invoke(LockState.Locked);
        }

        /// <summary>
        /// Accept new connections
        /// </summary>
        /// <param name="ar">Async Result</param>
        private void AcceptCallback(IAsyncResult ar)
        {
            Socket client = null;
            try
            {
                client = serverSocket.EndAccept(ar);
            }
            catch (Exception ex)
            {
                ServerError?.Invoke(ex);
                return;
            }
            DeviceConnected?.Invoke((IPEndPoint)client.RemoteEndPoint);

            ReadObject readObject = new ReadObject() { client = client, buffer = new byte[1024], isFirstMessage = true, session = new SessionCrypto() };
            client.BeginReceive(readObject.buffer, 0, readObject.buffer.Length, SocketFlags.None, new AsyncCallback(ReadCallback), readObject);
            serverSocket.BeginAccept(new AsyncCallback(AcceptCallback), null);
        }

        /// <summary>
        /// Read messages from the device
        /// </summary>
        /// <param name="ar">Async Result</param>
        private void ReadCallback(IAsyncResult ar)
        {
            int bytesRead = 0;
            bool noRead = false;
            ReadObject readObject = (ReadObject)ar.AsyncState;

            try
            {
                bytesRead = readObject.client.EndReceive(ar);
            }
            catch (Exception ex)
            {
                ServerError?.Invoke(ex);
                return;
            }

            if (bytesRead > 0)
            {
                if (readObject.isFirstMessage)
                {
                    string derPublicKey = keyGeneration.GetDerPublicKey();
                    SendString(readObject.client, derPublicKey);
                    Form1.WriteLine("Public Key Sent");
                    readObject.isFirstMessage = false;
                }
                else
                {
                    byte[] dataReceived = new byte[bytesRead];
                    Array.Copy(readObject.buffer, dataReceived, bytesRead);
                    string textData = Encoding.UTF8.GetString(dataReceived);

                    if (textData.StartsWith("set-session-key"))
                    {
                        Form1.WriteLine("Got set session key");
                        string encryptedSessionKey = textData.Substring(15);
                        string sessionKey = Encoding.UTF8.GetString(keyGeneration.DecryptData(Convert.FromBase64String(encryptedSessionKey)));
                        readObject.session.SetSessionKey(sessionKey);
                    }
                    else
                    {
                        Form1.WriteLine("Got session message");
                        byte[] sessionData = readObject.session.DecryptData(textData);
                        string sessionTextData = Encoding.UTF8.GetString(sessionData);
                        Form1.WriteLine($"Session Data: {sessionTextData}");
                        if (sessionTextData.StartsWith("res-"))
                        {
                            Form1.WriteLine("Got request setter");
                            readObject.requestString = sessionTextData.Substring(sessionTextData.IndexOf('-') + 1);
                            Form1.WriteLine($"Request string set to: {readObject.requestString}");
                            SendString(readObject.client, Convert.ToBase64String(readObject.session.EncryptData(Encoding.UTF8.GetBytes("no-data"))));
                            Form1.WriteLine("Continue message sent to client");
                        }
                        else if (sessionTextData.StartsWith("no-"))
                        {
                            Form1.WriteLine($"Couldn't find credentials on the device: {sessionTextData}");
                            string parameter = sessionTextData.Substring(sessionTextData.IndexOf('-') + 1);
                            if (parameter == "setup") LockStateChanged?.Invoke(LockState.Failed);
                            else if (parameter == "fp")
                            {
                                Form1.WriteLine("User failed to authenticate with fingerprint!");
                                if (readObject.requestString == "getkname-windowsLogon") WindowsLocking.CancelRegistration();
                                else if (readObject.requestString.StartsWith("pw-"))
                                {
                                    Form1.WriteLine("Password get failed");
                                    if (jsSrv != null) jsSrv.getPasswordQueue.UpdateState(readObject.requestString.Substring(3), JavascriptServer.CredentialTransferState.Failed);
                                }
                                else if (readObject.requestString.StartsWith("storpw-"))
                                {
                                    Form1.WriteLine("Password storage failed");
                                    if (jsSrv != null) jsSrv.getPasswordQueue.UpdateState(readObject.requestString.Substring(7), JavascriptServer.CredentialTransferState.Failed);
                                }
                                else if (readObject.requestString.StartsWith("getkname-"))
                                {
                                    Form1.WriteLine("Get key failed");
                                    if (jsSrv != null) jsSrv.getPasswordQueue.UpdateState(readObject.requestString.Substring(10), JavascriptServer.CredentialTransferState.Failed);
                                }
                            }

                            noRead = true;
                        }
                        else if (sessionTextData == "getuser")
                        {
                            if (jsSrv == null) throw new InvalidOperationException("Can't store password while javascript server is down");
                            object[] data = jsSrv.storePasswordQueue.GetQueueData(readObject.requestString.Substring(7));
                            if (data == null || data.Length != 2) throw new NullReferenceException("Can't find credentials for the specified web site hash");
                            readObject.credentials.username = (string)data[0];
                            readObject.credentials.password = (string)data[1];
                            SendString(readObject.client, Convert.ToBase64String(readObject.session.EncryptData(Encoding.UTF8.GetBytes(readObject.credentials.username))));
                        }
                        else if (sessionTextData == "getpass")
                        {
                            SendString(readObject.client, Convert.ToBase64String(readObject.session.EncryptData(Encoding.UTF8.GetBytes(readObject.credentials.password))));
                            if (jsSrv != null) jsSrv.storePasswordQueue.UpdateState(readObject.requestString.Substring(7), JavascriptServer.CredentialTransferState.Success);
                            DismissIfOpen?.Invoke();
                            noRead = true;
                        }
                        else if (sessionTextData.StartsWith("usresp-"))
                        {
                            string parameter = sessionTextData.Substring(sessionTextData.IndexOf('-') + 1);
                            readObject.credentials.username = parameter;
                            Form1.WriteLine($"Got credentials: usr: {readObject.credentials.username} ; pwd: {readObject.credentials.password}");
                            if (jsSrv == null) throw new NullReferenceException("Javascript Server was down when trying to get credentials data");
                            jsSrv.getPasswordQueue.UpdateExtraData(readObject.requestString.Substring(3), readObject.credentials.username, readObject.credentials.password);
                            jsSrv.getPasswordQueue.UpdateState(readObject.requestString.Substring(3), JavascriptServer.CredentialTransferState.Success);
                            noRead = true;
                        }
                        else if (sessionTextData.StartsWith("pushkey-"))
                        {
                            string key = sessionTextData.Substring(sessionTextData.IndexOf('-') + 1);

                            if (readObject.requestString == "win")
                            {
                                if (WindowsLocking.IsLogonValid(key)) LockStateChanged?.Invoke(LockState.Unlocked);
                                else LockStateChanged?.Invoke(LockState.Failed);
                            }
                            else if (readObject.requestString == "lock")
                            {
                                if (WindowsLocking.IsLogonValid(key)) LockStateChanged?.Invoke(LockState.Locked);
                                else LockStateChanged?.Invoke(LockState.Failed);
                            }
                            else
                            {
                                if (jsSrv == null) throw new NullReferenceException("Javascript server is down when trying to forward 2fa key");
                                jsSrv.getKeyQueue.UpdateExtraData(readObject.requestString.Substring(10), key);
                                jsSrv.getKeyQueue.UpdateState(readObject.requestString.Substring(10), JavascriptServer.CredentialTransferState.Success);
                            }

                            noRead = true;
                        }
                        else if (sessionTextData.StartsWith("pwresp-"))
                        {
                            string parameter = sessionTextData.Substring(sessionTextData.IndexOf('-') + 1);
                            readObject.credentials.password = parameter;
                            DismissIfOpen?.Invoke();
                        }
                        else if (sessionTextData == "getkvalue")
                        {
                            string parameter = readObject.requestString.Substring(readObject.requestString.IndexOf('-') + 1);
                            string pushKey;
                            if (parameter == "windowsLogon") //Windows Lock Authentication
                            {
                                string lockingKey = WindowsLocking.RegisterLogon();
                                pushKey = lockingKey;
                            }
                            else
                            {
                                if (jsSrv == null) throw new NullReferenceException("Javascript server was down when trying to send key to android device");
                                if (jsSrv.storeKeyQueue.Contains(readObject.requestString.Substring(9))) pushKey = (string)jsSrv.storeKeyQueue.GetQueueData(readObject.requestString.Substring(9))[0];
                                else pushKey = "fail";
                            }

                            if (pushKey == null) pushKey = "fail";

                            SendString(readObject.client, Convert.ToBase64String(readObject.session.EncryptData(Encoding.UTF8.GetBytes(pushKey))));
                            if (pushKey == "fail")
                            {
                                Form1.WriteLine("PushKey set to fail!");
                                jsSrv.storeKeyQueue.UpdateState(readObject.requestString.Substring(9), JavascriptServer.CredentialTransferState.Failed);
                            }
                            else jsSrv.storeKeyQueue.UpdateState(readObject.requestString.Substring(9), JavascriptServer.CredentialTransferState.Success);
                            noRead = true;
                        }
                    }
                }
            }

            Array.Clear(readObject.buffer, 0, readObject.buffer.Length);
            if (!noRead) readObject.client.BeginReceive(readObject.buffer, 0, readObject.buffer.Length, SocketFlags.None, new AsyncCallback(ReadCallback), readObject);
        }

        /// <summary>
        /// Send message to the device
        /// </summary>
        /// <param name="client">Target client</param>
        /// <param name="dataToSend">Message to send</param>
        private void SendString(Socket client, string dataToSend)
        {
            dataToSend = dataToSend.Replace("\r\n", "rpwenter\\n");
            dataToSend += "\n";
            byte[] byteData = Encoding.UTF8.GetBytes(dataToSend);
            client.Send(byteData, 0, byteData.Length, SocketFlags.None);
        }
    }
}