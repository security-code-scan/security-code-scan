using Microsoft.CodeAnalysis.Diagnostics;
using System;
using System.Collections.Generic;
using Microsoft.CodeAnalysis.VisualBasic.Syntax;
using RoslynSecurityGuard.Analyzers.Utils;

namespace RoslynSecurityGuard.Analyzers.Taint
{
    public class VbCodeEvaluation
    {
        public static List<CSharpTaintAnalyzerExtension> extensions { get; set; } = new List<CSharpTaintAnalyzerExtension>();

        public void VisitMethods(SyntaxNodeAnalysisContext ctx)
        {
            var node = ctx.Node as MethodBlockSyntax;
            try
            {
                if (node != null)
                {
                    var state = new ExecutionState(ctx);

                    /*foreach (var ext in extensions)
                    {
                        ext.VisitBeginMethodDeclaration(node, state);
                    }*/


                    //TODO: Implement VB code evaluation
                    //VisitMethodDeclaration(node, state);

                    /*foreach (var ext in extensions)
                    {
                        ext.VisitEndMethodDeclaration(node, state);
                    }*/
                }
            }
            catch (Exception e)
            {
                //Intercept the exception for logging. Otherwise, the analyzer will failed silently.
                string methodName = node.BlockStatement.ToString();
                string errorMsg = string.Format("Unhandle exception while visiting method: {0}", e.Message);
                SGLogging.Log(errorMsg);
                throw new Exception(errorMsg, e);
            }
        }
    }
}
