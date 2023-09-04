using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Management.Automation.Runspaces;
using System.Management.Automation;
using System.Text;
using System.Threading.Tasks;
using System.Dynamic;
using System.Text.Json;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using System.Diagnostics;
using System.Speech.Synthesis;

namespace ExchangeRunSpace
{
    public class ExchangeOnlineSession
    {
        public static void Connect(RunspacePool currentRunSpacePool)
        {


            Console.WriteLine("Attempting to Connect to Exchange Session");
            PowerShell myExchangePSInstanceInit = PowerShell.Create();
            myExchangePSInstanceInit.RunspacePool = currentRunSpacePool;
            myExchangePSInstanceInit.AddScript("Connect-ExchangeOnline");
            Collection<PSObject> exchangeResults = myExchangePSInstanceInit.Invoke();
            if (myExchangePSInstanceInit.HadErrors)
            {
                Console.WriteLine("Exchange Import PSInstance: Seems to have faced error...");
                foreach (var item in myExchangePSInstanceInit.Streams.Error)
                {
                    Console.WriteLine(item);
                }
            }
            else
            {

                Console.WriteLine("Exchange Import PSInstance: No errors...");
                myExchangePSInstanceInit.Commands.Clear();
                myExchangePSInstanceInit.AddScript("(Get-connectionInformation).ConnectionID.GUID");
                Collection<PSObject> exchangeResults2 = myExchangePSInstanceInit.Invoke();
                foreach (PSObject obj in exchangeResults2)
                {
                    Console.WriteLine("Exchange Connection ID :: " + obj.ToString());
                    myExchangePSInstanceInit.Dispose();
                }
            }
        }

        public static void Disconnect(RunspacePool currentRunSpacePool)
        {

            Console.WriteLine("Attempting to Disconnect Exchange Session");
            PowerShell myExchangePSInstanceClose = PowerShell.Create();
            myExchangePSInstanceClose.RunspacePool = currentRunSpacePool;
            myExchangePSInstanceClose.AddScript("Disconnect-ExchangeOnline -Confirm: $false");
            myExchangePSInstanceClose.Invoke();
            myExchangePSInstanceClose.Dispose();

        }
        public static string Execute(RunspacePool myRunSpacePool, List<string> psCommandsList)
        {

            List<PSInstanceWithResult> psInstanceCollectionWithResults = new List<PSInstanceWithResult>();

            dynamic psDataObject = new ExpandoObject();
            bool psCommandExecution = true;
            if (psCommandsList.Contains("Throw-Error")) { psCommandExecution = false; }
            string myJsonOutput = string.Empty;
            // Initiate execution of each command

            if (psCommandExecution)
            {
                foreach (string command in psCommandsList)
                {
                    PowerShell myPSInstance = PowerShell.Create();
                    myPSInstance.RunspacePool = myRunSpacePool;
                    myPSInstance.AddScript(command);
                    IAsyncResult asyncResults = myPSInstance.BeginInvoke();

                    PSInstanceWithResult currentPSInstanceWithResult = new PSInstanceWithResult();
                    currentPSInstanceWithResult.PowerShell = myPSInstance;
                    currentPSInstanceWithResult.PSInstanceResult = asyncResults;
                    psInstanceCollectionWithResults.Add(currentPSInstanceWithResult);
                }

                // Verify the status of the Execution to determine the latency..

                bool isStatusVerifcationComplete = false;
                int noOfInstancesYetToComplete = psInstanceCollectionWithResults.Count;
                Stopwatch myStopWatch = Stopwatch.StartNew();
                myStopWatch.Reset();
                myStopWatch.Start();
                while (!isStatusVerifcationComplete) {
                    
                    foreach (PSInstanceWithResult psInstance in psInstanceCollectionWithResults)
                    {
                        if (psInstance.ExecutionTime == -1)
                        {
                            PSInvocationState psCommandExecutionStatus = psInstance.PowerShell.InvocationStateInfo.State;
                            if (psCommandExecutionStatus == PSInvocationState.Completed ^ psCommandExecutionStatus == PSInvocationState.Disconnected ^ psCommandExecutionStatus == PSInvocationState.Failed)
                            {
                                psInstance.ExecutionTime = myStopWatch.ElapsedMilliseconds;
                                noOfInstancesYetToComplete--;
                            }
                        }

                    }
                    if (noOfInstancesYetToComplete == 0) { isStatusVerifcationComplete = true; }   
                }
                myStopWatch.Stop();

                // Collect the results from all PS Instances..
                int i = 1;
                foreach (PSInstanceWithResult psInstance in psInstanceCollectionWithResults)
                {

                    string keyCommandName = "CMD" + i;

                    MyDynamicObject.AddProperty(psDataObject, keyCommandName, psInstance.PowerShell.Commands.Commands[0].CommandText);
                    MyDynamicObject.AddProperty(psDataObject, keyCommandName+"_ExecutionTime(ms)", psInstance.ExecutionTime);

                    PSDataCollection<PSObject> commandResult = psInstance.PowerShell.EndInvoke(psInstance.PSInstanceResult);

                    if (psInstance.PowerShell.HadErrors)
                    {
                        string keyName = "CMD" + i + "Error";
                        Console.WriteLine("PS Instance {0} seem to have encountered error", psInstance.PowerShell.InstanceId);
                        // Get the error string
                        foreach (var errorString in psInstance.PowerShell.Streams.Error)
                        {
                            MyDynamicObject.AddProperty(psDataObject, keyName, errorString.ToString());
                        }
                    }
                    else
                    {

                        string keyName = "CMD" + i + "Results";

                        dynamic psDataChildObject = new ExpandoObject();

                        foreach (PSObject obj in commandResult)
                        {
                            int j = 0;
                            foreach (var item in obj.Properties)
                            {
                                j++;
                                //Console.WriteLine(item.Name + " : " + item.Value);
                                MyDynamicObject.AddProperty(psDataChildObject, item.Name, item.Value);
                                if (j == 10) { break; }
                            }
                        }

                        foreach (var item in psDataChildObject)
                        {
                            //Console.WriteLine(item.Key + " : " + item.Value);
                        }

                        MyDynamicObject.AddProperty(psDataObject, keyName, psDataChildObject);
                        psInstance.PowerShell.Dispose();
                    }

                    i++;
                }

            }

            else { 
            
                MyDynamicObject.AddProperty(psDataObject,"Error", "Unsupported Request");
            }

            JsonSerializerOptions myJsonOptions = new JsonSerializerOptions();
            myJsonOptions.WriteIndented = true;
            //myJsonOptions.ReferenceHandler = ReferenceHandler.Preserve;
            myJsonOutput = JsonSerializer.Serialize(psDataObject, myJsonOptions);
            return myJsonOutput;

        }

    }
}
