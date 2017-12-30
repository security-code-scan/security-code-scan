using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityCodeScan.Analyzers.Utils
{
    public class CodeFixUtil
    {

        /// <summary>
        /// Extract the last indendation from the trivia passed.
        /// </summary>
        /// <param name="leadingTrivia"></param>
        /// <returns></returns>
        public static SyntaxTriviaList KeepLastLine(SyntaxTriviaList leadingTrivia)
        {
            SyntaxTriviaList triviaBuild = SyntaxTriviaList.Empty;
            foreach (SyntaxTrivia trivium in leadingTrivia.Reverse())
            {
                if (trivium.IsKind(SyntaxKind.WhitespaceTrivia))
                {
                    triviaBuild = triviaBuild.Insert(0, trivium);
                    break;
                }
            }
            return triviaBuild;
        }

        public static SyntaxNode GetParentNode(SyntaxNode childNode, Type target)
        {
            SyntaxNode node = childNode;
            
            do {
                node = node.Parent;
            } while (node.Parent != null && node.GetType() != target);

            return node.GetType() == target ? node : null;
        }
    }
}
