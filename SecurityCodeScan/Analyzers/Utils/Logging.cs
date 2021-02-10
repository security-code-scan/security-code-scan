#nullable disable
using System;

namespace SecurityCodeScan.Analyzers.Utils
{
    /// <summary>
    /// Logging utility to debug the analyzers
    /// </summary>
    internal class Logger
    {
        public static Action<string> LoggerHandler { get; set; }

        /// <summary>
        /// An action is set to handle the log to print to the console, redirect to the file system or anything else..
        /// </summary>
        /// <returns></returns>
        public static bool IsConfigured()
        {
            return LoggerHandler != null;
        }

        public static void Log(string message,
                               bool   includeCallerInfo = true,
                               [System.Runtime.CompilerServices.CallerMemberName]
                               string memberName = "",
                               [System.Runtime.CompilerServices.CallerFilePath]
                               string sourceFilePath = "",
                               [System.Runtime.CompilerServices.CallerLineNumber]
                               int sourceLineNumber = 0)
        {
            if (!IsConfigured())
                return;

            if (includeCallerInfo) //Display the filename of the class calling the logging API
            {
                int indexBackSlash    = sourceFilePath.LastIndexOf("\\", StringComparison.Ordinal);
                int indexForwardSlash = sourceFilePath.LastIndexOf("//", StringComparison.Ordinal);

                int lastSlash = Math.Max(Math.Max(indexBackSlash, indexForwardSlash) + 1, 0);

                LoggerHandler("[" + sourceFilePath.Substring(lastSlash) + ":" + sourceLineNumber + " " + memberName + "]");
            }

            LoggerHandler(message);
        }
    }
}
