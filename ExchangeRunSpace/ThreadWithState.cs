using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using ExchangeRunSpace;

namespace ExchangeRunSpace
{
    public class ThreadWithState
    {
        // State information used in the task.
        private RunspacePool myRunSpacePool;
        private TcpClient myClient;
        private List<Thread> myThreads;

        // The constructor obtains the state information.
        public ThreadWithState(RunspacePool currentRunSpacePool, TcpClient currentClient, List<Thread> currentThreads)
        {
            myRunSpacePool = currentRunSpacePool;
            myClient = currentClient;
            myThreads = currentThreads;
        }

        // The thread procedure performs the task, such as formatting
        // and printing a document.
        public void ThreadProc()
        {
           
            var Bytes = new Byte[1024];
            string data = null;

            NetworkStream stream = myClient.GetStream();

            // Read the data sent by the client
            int i = stream.Read(Bytes, 0, Bytes.Length);

            // Translate from bytes (came over the network) into human readable string..

            data = System.Text.Encoding.ASCII.GetString(Bytes, 0, i);
            Console.WriteLine("Thread TID: {0}, RemoteEndPoint: {1}, Requested Received.", Thread.CurrentThread.ManagedThreadId, myClient.Client.RemoteEndPoint);

            // Do your Task here...

            List<string> psCommandsList = HTTPData.GetPSCommand(data);

            string jsonResponseString = ExchangeOnlineSession.Execute(myRunSpacePool, psCommandsList);
           
            string response = "HTTP/1.1 200 OK\r\nContent-Type:application/json\r\n\r\n" + jsonResponseString;
            byte[] responsedata = System.Text.Encoding.ASCII.GetBytes(response);

            stream.Write(responsedata, 0, responsedata.Length);
            Console.WriteLine("Thread TID: {0}, RemoteEndPoint: {1}, Response Sent.", Thread.CurrentThread.ManagedThreadId, myClient.Client.RemoteEndPoint);
            stream.Close();
            myClient.Close();

            // At the end of the task, Remove this thread from the Thread collection
            myThreads.Remove(Thread.CurrentThread);
        }


    }
}
