using System;

namespace RoslynSecurityGuard.Analyzers.Utils
{
    /// <summary>
    /// Logging utility to debug the analyzers
    /// </summary>
    public class SGLogging
    {
        public static Action<string> LoggerHandler { get; set; }

        /// <summary>
        /// An action is set to handle the log to print to the console, redirect to the filesystem or anything else..
        /// </summary>
        /// <returns></returns>
        public static bool IsConfigured() {
            return LoggerHandler != null;
        }

        public static void Log(string message,
            bool includeCallerInfo = true,
            [System.Runtime.CompilerServices.CallerMemberName] string memberName = "",
            [System.Runtime.CompilerServices.CallerFilePath] string sourceFilePath = "",
            [System.Runtime.CompilerServices.CallerLineNumber] int sourceLineNumber = 0) {
            //CompilerServices annotations are needed because

            if (!IsConfigured()) return; //No logger set, leave ship!

            if (includeCallerInfo) //Display the filename of the class calling the logging API
            {
                int indexBackSlash = sourceFilePath.LastIndexOf("\\");
                int indexForwardSlash = sourceFilePath.LastIndexOf("//");

                int lastSlash = Math.Max(Math.Max(indexBackSlash,indexForwardSlash),0);

                LoggerHandler("[" + sourceFilePath.Substring(lastSlash) + ":" + sourceLineNumber + " " + memberName + "]");
            }
            LoggerHandler(message);
        }
    }
}
