using System.Collections.ObjectModel;
using System.Management.Automation;
using System.Management.Automation.Host;
using System.Management.Automation.Runspaces;
using System.Net.Sockets;
using System.Net;
using System.Threading;
using ExchangeRunSpace;

// See https://aka.ms/new-console-template for more information

RunspacePool mainRunSpacePool = RunspaceFactory.CreateRunspacePool();
mainRunSpacePool.InitialSessionState.ThrowOnRunspaceOpenError = true;
mainRunSpacePool.InitialSessionState.ExecutionPolicy = Microsoft.PowerShell.ExecutionPolicy.Unrestricted;
mainRunSpacePool.SetMaxRunspaces(1000);
mainRunSpacePool.Open();

// Connect Exchange Session in the RunSpacePool
ExchangeOnlineSession.Connect(mainRunSpacePool);

Console.WriteLine("**** Supported URLs ******* \r\n    /profile/mailboxes/{UPN}\r\n    /mailboxes/{UPN}\r\n    /mailbox-stats/{UPN}\r\n    /archive-mailbox-stats/{UPN}\r\n    /mbx-folder-stats/{UPN} \r\n******");


// Start the TCP Server and Get the client connection

int port = 8080;
IPAddress localAddress = IPAddress.Parse("127.0.0.2");
TcpListener server = new TcpListener(localAddress, port);
server.Start();
Console.WriteLine("Server Started...");

// Collect the list of Threads
List<Thread> childThreads = new List<Thread>();

int noOfRequests = 1;

while (noOfRequests < 500)
{

    Console.WriteLine("Waiting for connection attempt # {0}...", noOfRequests);
    TcpClient mainClient = server.AcceptTcpClient();

    // Supply the state information required by the task.
    ThreadWithState tws = new ThreadWithState(mainRunSpacePool, mainClient, childThreads);

    // Create a thread to execute the task, and then
    // start the thread.
    Thread t = new Thread(new ThreadStart(tws.ThreadProc));
    t.Start();
    childThreads.Add(t);

    noOfRequests++;

}

var currentChildThreads = childThreads.ToArray();
foreach (var item in currentChildThreads) {

    while (item.IsAlive) {
        Console.WriteLine("TID: {0} Procedure seems to be not completed...", item.ManagedThreadId.ToString());
        Console.WriteLine("Will wait for 3 seconds and check back...");
        Thread.Sleep(3000);
    }

}

Console.WriteLine("Completed verifying the 'Alive' state of all the threads..");

// Disconnect Exchange Session before closing the pool...
ExchangeOnlineSession.Disconnect(mainRunSpacePool);

// Close the RunSpace Pool
mainRunSpacePool.Close();

Console.WriteLine("Main Program reached the END..");