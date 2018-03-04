using System.Collections.Generic;

namespace FingerPrintAuthenticator
{
    /// <summary>
    /// Queue Providing Class For Cross Server Operations
    /// </summary>
    class QueueManager
    {
        /// <summary>
        /// The underlying queue object
        /// </summary>
        private Dictionary<string, QueueData> queue;

        /// <summary>
        /// Init the queue
        /// </summary>
        public QueueManager()
        {
            queue = new Dictionary<string, QueueData>();
        }

        /// <summary>
        /// Add an item to the queue
        /// </summary>
        /// <param name="urlHash">The hashed url of the operation</param>
        public void Add(string urlHash)
        {
            queue.Add(urlHash, new QueueData() { State = JavascriptServer.CredentialTransferState.Pending });
        }

        public bool Contains(string urlHash)
        {
            foreach (KeyValuePair<string, QueueData> kvp in queue)
            {
                if (kvp.Key == urlHash) return true;
            }

            return false;
        }

        /// <summary>
        /// Update the state of an operation
        /// </summary>
        /// <param name="urlHash">The hashed url of the operation</param>
        /// <param name="state">The new state of the operation</param>
        public void UpdateState(string urlHash, JavascriptServer.CredentialTransferState state)
        {
            if (queue.ContainsKey(urlHash)) queue[urlHash].State = state;
        }

        /// <summary>
        /// Add extra data to the operation
        /// </summary>
        /// <param name="urlHash">The hashed url of the operation</param>
        /// <param name="extraData">The extra data to add</param>
        public void UpdateExtraData(string urlHash, params object[] extraData)
        {
            if (queue.ContainsKey(urlHash)) queue[urlHash].ExtraData = extraData;
        }

        /// <summary>
        /// Remove an operation from the queue
        /// </summary>
        /// <param name="urlHash">The hashed url of the operation</param>
        public void Remove(string urlHash)
        {
            if (queue.ContainsKey(urlHash)) queue.Remove(urlHash);
        }

        /// <summary>
        /// Clear the queue
        /// </summary>
        public void Clear()
        {
            queue.Clear();
        }

        /// <summary>
        /// Get the state of an operation
        /// </summary>
        /// <param name="urlHash">The hased url of the operation</param>
        /// <returns>The state of the operation</returns>
        public JavascriptServer.CredentialTransferState GetQueueState(string urlHash)
        {
            return (queue.TryGetValue(urlHash, out QueueData qData)) ? qData.State : JavascriptServer.CredentialTransferState.Failed; //Return failed, because we don't want to receive endless number of requests from the browser
        }

        /// <summary>
        /// Get extra data of the operation
        /// </summary>
        /// <param name="urlHash">The hashed url of the operation</param>
        /// <returns>An object array containing each added data</returns>
        public object[] GetQueueData(string urlHash)
        {
            return (queue.TryGetValue(urlHash, out QueueData qData)) ? qData.ExtraData : null;
        }
    }

    /// <summary>
    /// Class for queue value
    /// </summary>
    class QueueData
    {
        /// <summary>
        /// The state of the operation
        /// </summary>
        public JavascriptServer.CredentialTransferState State { get; set; }
        /// <summary>
        /// Object array for storing extra data
        /// </summary>
        internal object[] ExtraData { get; set; }
    }
}
