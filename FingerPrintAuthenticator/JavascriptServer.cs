using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace FingerPrintAuthenticator
{
    /// <summary>
    /// Communicates with Chrome browser extensions via localhost
    /// </summary>
    class JavascriptServer
    {
        /// <summary>
        /// The server socket handling the data
        /// </summary>
        private Socket serverSocket;
        /// <summary>
        /// The endpoint to bind the server to
        /// </summary>
        private readonly IPEndPoint ep = new IPEndPoint(IPAddress.Loopback, 80);
        /// <summary>
        /// Incremental request tracking number
        /// </summary>
        private int clientTracker = 0;
        /// <summary>
        /// Client session data store
        /// </summary>
        private Dictionary<int, ReadObject> trackers = new Dictionary<int, ReadObject>();
        /// <summary>
        /// Object for locking tracker id generations
        /// </summary>
        private object idLockerObject = new object();
        /// <summary>
        /// Object fro locking session data store
        /// </summary>
        private object trackerLockObject = new object();
        /// <summary>
        /// Context reference
        /// </summary>
        private Form1 ctx;
        /// <summary>
        /// Password store request queue
        /// </summary>
        public QueueManager storePasswordQueue;
        /// <summary>
        /// Password get request queue
        /// </summary>
        public QueueManager getPasswordQueue;
        public QueueManager getKeyQueue;
        public QueueManager storeKeyQueue;

        /// <summary>
        /// Init the javascript server
        /// </summary>
        /// <param name="context">The parent Form1 object</param>
        public JavascriptServer(Form1 context)
        {
            ctx = context;
            getPasswordQueue = new QueueManager();
            getKeyQueue = new QueueManager();
            storeKeyQueue = new QueueManager();
            storePasswordQueue = new QueueManager();
        }

        /// <summary>
        /// Get the credentials of a store request
        /// </summary>
        /// <param name="urlHash">The hashed url of the credentials</param>
        /// <returns>Tuple with credentials. First item is the username, second is the password</returns>
        public Tuple<string, string> GetCredentials(string urlHash)
        {
            lock (trackerLockObject)
            {
                foreach (KeyValuePair<int, ReadObject> kvp in trackers)
                {
                    if (kvp.Value.urlHash == urlHash)
                        return new Tuple<string, string>(kvp.Value.userName, kvp.Value.password);
                } 
            }

            return null;
        }

        /// <summary>
        /// Credential Information Transfer State
        /// </summary>
        public enum CredentialTransferState
        {
            /// <summary>
            /// Server still working to get the data
            /// </summary>
            Pending,
            /// <summary>
            /// Server got the data
            /// </summary>
            Success,
            /// <summary>
            /// Server failed to get the required data
            /// </summary>
            Failed
        }

        /// <summary>
        /// HTTP Request Object
        /// </summary>
        private struct HTTPRequest
        {
            /// <summary>
            /// Request Method
            /// </summary>
            public string method;
            /// <summary>
            /// The requested URL
            /// </summary>
            public string resource;
            /// <summary>
            /// Request headers
            /// </summary>
            public List<string> headers;
            /// <summary>
            /// The body of the request
            /// </summary>
            public string requestData;
            /// <summary>
            /// True if first data not sent in the current request
            /// </summary>
            public bool firstData;
            /// <summary>
            /// The content length header
            /// </summary>
            public int contentLength;
        }

        /// <summary>
        /// Session Data for clients
        /// </summary>
        private struct ReadObject
        {
            /// <summary>
            /// The client's socket
            /// </summary>
            public Socket client;
            /// <summary>
            /// The buffer to read data to
            /// </summary>
            public byte[] buffer;
            /// <summary>
            /// Content Length header
            /// </summary>
            public int contentLength;
            /// <summary>
            /// Client session tracker ID
            /// </summary>
            public int cTracker;
            /// <summary>
            /// Username for store/get request
            /// </summary>
            public string userName;
            /// <summary>
            /// Password for store/get request
            /// </summary>
            public string password;
            /// <summary>
            /// Hashed URL for store/get request
            /// </summary>
            public string urlHash;
            /// <summary>
            /// HTTP Request Object
            /// </summary>
            public HTTPRequest http;
        }

        /// <summary>
        /// Start the javascript server
        /// </summary>
        public void StartServer()
        {
            serverSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            serverSocket.Bind(ep);
            serverSocket.Listen(5);
            serverSocket.BeginAccept(new AsyncCallback(AcceptCallback), null);
        }

        /// <summary>
        /// Stop the javascript server
        /// </summary>
        public void CloseServer()
        {
            try
            {
                serverSocket.Close();
                serverSocket.Dispose();
                serverSocket = null;
                trackers.Clear();
                trackers = null;
            }
            catch (Exception)
            {
                throw;
            }
        }

        /// <summary>
        /// Accept browser connections 
        /// </summary>
        /// <param name="ar">Async Result Object</param>
        private void AcceptCallback(IAsyncResult ar)
        {
            try
            {
                Socket clientSocket = serverSocket.EndAccept(ar);
                ReadObject readObject = new ReadObject()
                {
                    client = clientSocket,
                    buffer = new byte[1024],
                    contentLength = 0,
                    http = new HTTPRequest() { firstData = true }
                };

                clientSocket.BeginReceive(readObject.buffer, 0, readObject.buffer.Length, SocketFlags.None, new AsyncCallback(ReadCallback), readObject);
            }
            catch (Exception)
            {
                throw;
            }

            serverSocket.BeginAccept(new AsyncCallback(AcceptCallback), null);
        }

        /// <summary>
        /// Read data from the browser request
        /// </summary>
        /// <param name="ar">Async Result Object</param>
        private void ReadCallback(IAsyncResult ar)
        {
            int bytesRead = -1;
            ReadObject readObject = (ReadObject)ar.AsyncState;

            try
            {
                bytesRead = readObject.client.EndReceive(ar);
            }
            catch (Exception)
            {
                throw;
            }

            if (bytesRead > 0)
            {
                string textData = Encoding.ASCII.GetString(readObject.buffer, 0, bytesRead); //Get the HTTP Request

                if (readObject.http.firstData) //First request data
                {
                    readObject.http.firstData = false; //Next request isn't first
                    string[] dataLines = textData.Split(new String[] { "\r\n" }, StringSplitOptions.None); //Get the lines of the request
                    string requestLine = "";
                    readObject.http.headers = new List<string>();
                    readObject.http.requestData = "";
                    bool addRequestData = false; //True if request body should be created
                    foreach (string line in dataLines)
                    {
                        if (requestLine == "") requestLine = line; //First line is always request line
                        else if (line == "") addRequestData = true; //Empty line means end of headers
                        else if (!addRequestData) readObject.http.headers.Add(line); //Add headers if not ended
                        else if (addRequestData) readObject.http.requestData += line; //Append request body if headers ended
                    }

                    //Parse the content length
                    readObject.http.contentLength = -1;

                    foreach (string header in readObject.http.headers)
                    {
                        if (header.StartsWith("Content-Length: "))
                        {
                            int delimiter = header.IndexOf(':') + 2;
                            readObject.http.contentLength = int.Parse(header.Substring(delimiter));
                        }
                    }

                    string[] reqLineParts = requestLine.Split(' ');
                    readObject.http.method = reqLineParts[0]; //Set the request method
                    readObject.http.resource = reqLineParts[1].Substring(1); //Set the requested URL
                }
                else //Request fragmented, append the request body
                {
                    readObject.http.requestData += textData;
                }


                if (readObject.http.contentLength != -1 && ((readObject.http.contentLength > 0 && readObject.http.requestData == "") ||
                    (readObject.http.contentLength != readObject.http.requestData.Length))) //Browser didn't send the request (full) body in this message
                {
                    Form1.WriteLine("Request fragmented");
                }
                else //The request is fully appended
                {
                    Form1.WriteLine("Request completed");
                    HandleRequest(readObject.http.headers, readObject, readObject.http.method, readObject.http.resource, readObject.http.requestData); //Handle the request
                    readObject.http = new HTTPRequest() { firstData = true }; //Reset the request related data
                    Form1.WriteLine("Request handled");
                }

                Array.Clear(readObject.buffer, 0, readObject.buffer.Length); //Clear receive buffer
                readObject.client.BeginReceive(readObject.buffer, 0, readObject.buffer.Length, SocketFlags.None, new AsyncCallback(ReadCallback), readObject); //Receive again from the stream
            }
        }

        /// <summary>
        /// Handle a full HTTP Request
        /// </summary>
        /// <param name="headers">Headers of the request</param>
        /// <param name="readObject">The client's session data</param>
        /// <param name="method">The method of the request</param>
        /// <param name="resource">The requested function</param>
        /// <param name="requestData">The body of the request</param>
        private void HandleRequest(List<string> headers, ReadObject readObject, string method, string resource, string requestData)
        {
            bool gotTracker = false; //True if client sent tracker in the headers

            //Check if client sent header
            foreach (string header in headers)
            {
                if (header.StartsWith("Client-Tracker"))
                {
                    int delimiter = header.IndexOf(':') + 2; //The : and the space => 2
                    string value = header.Substring(delimiter);
                    if (int.TryParse(value, out int tracker))
                    {
                        lock (trackerLockObject)
                        {
                            if (trackers.TryGetValue(tracker, out ReadObject tempReadObject))
                            {
                                readObject = tempReadObject;
                                gotTracker = true;
                            }
                            else Form1.WriteLine("Client not registered with this ID");
                        }
                    }
                    else
                    {
                        Form1.WriteLine("Can't parse client tracker");
                    }

                    break;
                }
            }

            if (method == "POST" && gotTracker) //POST Functions
            {
                if (resource == "stor-pw") //Store password on phone
                {
                    string userName = null;
                    string password = null;

                    int userNameLength = int.Parse(requestData.Substring(0, 10));
                    userName = requestData.Substring(10, userNameLength);
                    int passwordLength = int.Parse(requestData.Substring(10 + userNameLength, 10));
                    password = requestData.Substring(20 + userNameLength, passwordLength);
                    string url = requestData.Substring(20 + userNameLength + passwordLength);

                    if (password != null && userName != null)
                    {
                        Form1.WriteLine($"Requested Password Storage: usr:{userName} ; pwd:{password}; url:{url}");
                        readObject.urlHash = SessionCrypto.DigestMessage(url);
                        readObject.userName = userName;
                        readObject.password = password;
                        storePasswordQueue.Add(readObject.urlHash);
                        storePasswordQueue.UpdateExtraData(readObject.urlHash, userName, password);
                        ctx.RequestPasswordStore(url);
                        SendMessage(readObject.client, "stor-init");
                    }
                }
                else if (resource == "getpw") //Get password from phone
                {
                    readObject.urlHash = SessionCrypto.DigestMessage(requestData);
                    getPasswordQueue.Add(readObject.urlHash);
                    ctx.RequestPasswordGet(readObject.urlHash);
                    SendMessage(readObject.client, "ok");
                }
                else if (resource == "getkey")
                {
                    readObject.urlHash = SessionCrypto.DigestMessage(requestData);
                    getKeyQueue.Add(readObject.urlHash);
                    ctx.RequestKeyGet(readObject.urlHash);
                    SendMessage(readObject.client, "get-ok");
                }
                else if (resource == "pushkey")
                {
                    int urlLength = int.Parse(requestData.Substring(0, 10));
                    string url = requestData.Substring(10, urlLength);
                    int tokenLength = int.Parse(requestData.Substring(10 + urlLength, 10));
                    string token = requestData.Substring(20 + urlLength, tokenLength);
                    readObject.urlHash = SessionCrypto.DigestMessage(url);
                    storeKeyQueue.Add(readObject.urlHash);
                    storeKeyQueue.UpdateExtraData(readObject.urlHash, token);
                    ctx.RequestKeyStore(readObject.urlHash);
                    SendMessage(readObject.client, "push-ok");
                    Form1.WriteLine($"ReadObject url hashed: {readObject.urlHash}");
                }

                readObject.contentLength = 0;
            }
            else if (method == "GET") //Get functions
            {
                if (resource == "tracker") //Client requested a new tracker ID
                {
                    lock (idLockerObject)
                    {
                        readObject.cTracker = clientTracker;
                        SendMessage(readObject.client, clientTracker.ToString());
                        clientTracker++;
                    }
                }
                else if (!gotTracker) //Drop if not setting tracker and tracker is not set
                {
                    Form1.WriteLine("GET without tracker and not setting tracker");
                }
                else if (resource == "stor-state") //Get the state of storing the password on the phone
                {
                    CredentialTransferState qState = storePasswordQueue.GetQueueState(readObject.urlHash);
                    switch (qState)
                    {
                        case CredentialTransferState.Success:
                            storePasswordQueue.Remove(readObject.urlHash);
                            SendMessage(readObject.client, "stor-completed");
                            Form1.WriteLine("Store confirmed");
                            break;
                        case CredentialTransferState.Failed:
                            SendMessage(readObject.client, "stor-fail");
                            storePasswordQueue.Remove(readObject.urlHash);
                            Form1.WriteLine("Store fail alert sent to the browser");
                            break;
                        default:
                            SendMessage(readObject.client, "stor-pending");
                            break;
                    }
                }
                else if (resource == "get-state") //Get the state of getting hte password from the phone
                {
                    CredentialTransferState qState = getPasswordQueue.GetQueueState(readObject.urlHash);

                    switch (qState)
	                {
                        case CredentialTransferState.Success:
                            object[] extraData = getPasswordQueue.GetQueueData(readObject.urlHash);
                            Tuple<string, string> credentials = new Tuple<string, string>((string)extraData[0], (string)extraData[1]);
                            getPasswordQueue.Remove(readObject.urlHash);
                            SendMessage(readObject.client, $"get-ok{EncodeBodyData(new string[] { credentials.Item1, credentials.Item2 })}");
                            Form1.WriteLine("Password sent to browser");
                            break;
                        case CredentialTransferState.Failed:
                            SendMessage(readObject.client, "get-fail");
                            getPasswordQueue.Remove(readObject.urlHash);
                            Form1.WriteLine("Password fail alert sent to the browser");
                            break;
                        default:
                            SendMessage(readObject.client, "get-pending");
                            break;
                    }
                }
                else if (resource == "kget-state")
                {
                    CredentialTransferState qState = getKeyQueue.GetQueueState(readObject.urlHash);

                    switch (qState)
                    {
                        case CredentialTransferState.Success:
                            object[] extraData = getKeyQueue.GetQueueData(readObject.urlHash);
                            string keyToken = (string)extraData[0];
                            getKeyQueue.Remove(readObject.urlHash);
                            SendMessage(readObject.client, $"get-ok{keyToken}");
                            Form1.WriteLine("Key sent to browser");
                            break;
                        case CredentialTransferState.Failed:
                            SendMessage(readObject.client, "get-fail");
                            getKeyQueue.Remove(readObject.urlHash);
                            Form1.WriteLine("Key fail alert sent to the browser");
                            break;
                        default:
                            SendMessage(readObject.client, "get-pending");
                            break;
                    }
                }
                else if (resource == "kpush-state")
                {
                    Form1.WriteLine($"ReadObject url hash: {readObject.urlHash}");
                    Form1.WriteLine($"ReadObject client tracker: {readObject.cTracker}");
                    CredentialTransferState qState = storeKeyQueue.GetQueueState(readObject.urlHash);

                    switch (qState)
                    {
                        case CredentialTransferState.Success:
                            object[] extraData = storeKeyQueue.GetQueueData(readObject.urlHash);
                            storeKeyQueue.Remove(readObject.urlHash);
                            SendMessage(readObject.client, $"push-ok");
                            Form1.WriteLine("Key installed on android");
                            break;
                        case CredentialTransferState.Failed:
                            SendMessage(readObject.client, "push-fail");
                            storeKeyQueue.Remove(readObject.urlHash);
                            Form1.WriteLine("Key install failed in android");
                            break;
                        default:
                            SendMessage(readObject.client, "push-pending");
                            break;
                    }
                }

                readObject.contentLength = 0;
            }
            else if (method == "OPTIONS")
            {
                SendMessage(readObject.client, "", "\r\nAccess-Control-Allow-Headers: Client-Tracker");
                Form1.WriteLine("Options response sent");
                readObject.contentLength = 0;
                return;
            }
            else if (!gotTracker) //POST Request (or other?) without tracker
            {
                Form1.WriteLine("Tracker not sent with!");
                readObject.contentLength = 0;
                return;
            }
            else //Invalid request but tracker is set? wierd
            {
                Form1.WriteLine("Invalid Request Type");
                readObject.contentLength = 0;
                return;
            }

            //Store the session data
            lock (trackerLockObject)
            {
                if (trackers.ContainsKey(readObject.cTracker)) trackers[readObject.cTracker] = readObject;
                else trackers.Add(readObject.cTracker, readObject);
            }
        }

        /// <summary>
        /// Encode multiple values to one request body
        /// </summary>
        /// <param name="dataToEncode">An array of values to encode</param>
        /// <returns>The encoded string to send</returns>
        private string EncodeBodyData(string[] dataToEncode)
        {
            StringBuilder finalResult = new StringBuilder();

            foreach (string key in dataToEncode)
            {
                string strDataLength = key.Length.ToString();
                for (int i = 10 - strDataLength.Length; i > 0; i--)
                {
                    finalResult.Append("0");
                }

                finalResult.Append(strDataLength);
                finalResult.Append(key);
            }

            return finalResult.ToString();
        }

        /// <summary>
        /// Send message to the browser
        /// </summary>
        /// <param name="client">Client to send the message to</param>
        /// <param name="message">Response body</param>
        /// <param name="extraHeaders">Additional response headers</param>
        private void SendMessage(Socket client, string message, string extraHeaders = "")
        {
            string httpPayload = $"HTTP/1.1 200 OK\r\nServer: fpauth javascript server\r\nDate: {DateTime.Now.ToString()}\r\nContent-Type: text/plain\r\n" +
                $"Access-Control-Allow-Origin: *\r\nContent-Length: {message.Length}{extraHeaders}" +
                $"\r\n\r\n{message}";
            byte[] dataBytes = Encoding.GetEncoding("ISO-8859-1").GetBytes(httpPayload);
            client.Send(dataBytes, 0, dataBytes.Length, SocketFlags.None);
        }
    }
}