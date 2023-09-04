using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

/*   Supported URL Paths....
    /profile/mailboxes/{UPN}
    /mailboxes/{UPN}
    /mailbox-stats/{UPN}
    /archive-mailbox-stats/{UPN}
    /mbx-folder-stats/{UPN}

 */ 


namespace ExchangeRunSpace
{
    public class HTTPData
    {

        public static List<string> GetPSCommand(string inputURL)
        {

            List<string> psCommands = new List<string>();
            string input = inputURL;

            // Trim double quotes
            string input1 = input.Trim('"');

            // Check if the HTTP method is GET
            bool isHTTPGET = input1.StartsWith("GET");

            if (isHTTPGET)
            {
                // Split by Whitespaces
                string[] result = input1.Split(" ");
                string url = result[1];

                // Split by backslash
                string[] urlpaths = url.Split("/");

                //Determine the right function using the URL..."
                switch (urlpaths[1])
                {
                    case "profile":
                        switch (urlpaths[2])
                        {
                            case "mailboxes":
                                if (urlpaths[3] != null & urlpaths[3] != string.Empty)
                                {
                                    psCommands.Add("Get-EXOMailbox -UserPrincipalName " + urlpaths[3]);
                                    psCommands.Add("Get-EXOMailboxStatistics -UserPrincipalName " + urlpaths[3]);
                                    psCommands.Add("Get-EXOMailboxFolderStatistics -UserPrincipalName " + urlpaths[3]);
                                    psCommands.Add("Get-EXOMailboxStatistics -Archive -UserPrincipalName " + urlpaths[3]);
                                }
                                else { psCommands.Add("Throw-Error"); }
                                break;
                            default: psCommands.Add("Throw-Error"); break;
                        }
                        break;
                    
                    case "mailboxes":
                        if (urlpaths[2] != null & urlpaths[2] != string.Empty) { psCommands.Add("Get-EXOMailbox -UserPrincipalName " + urlpaths[2]); }
                        else { psCommands.Add("Throw-Error"); }
                        break;


                    case "mailbox-stats":
                        if (urlpaths[2] != null & urlpaths[2] != string.Empty) { psCommands.Add("Get-EXOMailboxStatistics -UserPrincipalName " + urlpaths[2]); }
                        else { psCommands.Add("Throw-Error"); }
                        break;

                    case "archive-mailbox-stats":
                        if (urlpaths[2] != null & urlpaths[2] != string.Empty) { psCommands.Add("Get-EXOMailboxStatistics -Archive -UserPrincipalName " + urlpaths[2]); }
                        else { psCommands.Add("Throw-Error"); }
                        break;

                    case "mbx-folder-stats":
                        if (urlpaths[2] != null & urlpaths[2] != string.Empty) { psCommands.Add("Get-EXOMailboxFolderStatistics -UserPrincipalName " + urlpaths[2]); }
                        else { psCommands.Add("Throw-Error"); }
                        break;

                    default: psCommands.Add("Throw-Error"); break;
                }
            }

            else
            {

                psCommands.Add("Throw-Error");
            }
            return psCommands;
        }
    }
}
