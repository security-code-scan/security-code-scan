using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;

namespace SecurityCodeScan.Analyzers.Utils
{
    internal class CodeFixUtil
    {
        /// <summary>
        /// Extract the last indentation from the trivia passed.
        /// </summary>
        /// <param name="leadingTrivia"></param>
        /// <returns></returns>
        public static SyntaxTriviaList KeepLastLine(SyntaxTriviaList leadingTrivia)
        {
            SyntaxTriviaList triviaBuild = SyntaxTriviaList.Empty;
            foreach (SyntaxTrivia trivium in leadingTrivia.Reverse())
            {
                if (!trivium.IsKind(SyntaxKind.WhitespaceTrivia))
                    continue;

                triviaBuild = triviaBuild.Insert(0, trivium);
                break;
            }

            return triviaBuild;
        }
    }
}
