using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using SecurityCodeScan.Analyzers.Locale;
using CSharp = Microsoft.CodeAnalysis.CSharp;
using CSharpSyntax = Microsoft.CodeAnalysis.CSharp.Syntax;
using VB = Microsoft.CodeAnalysis.VisualBasic;
using VBSyntax = Microsoft.CodeAnalysis.VisualBasic.Syntax;

namespace SecurityCodeScan.Analyzers
{
    [DiagnosticAnalyzer(LanguageNames.CSharp, LanguageNames.VisualBasic)]
    public class XssPreventionAnalyzer : DiagnosticAnalyzer
    {
        public const string DiagnosticId = "SCS0029";

        private List<string> EncodingMethods = new List<string>
        {
            "HtmlEncoder.Default.Encode",
            "HttpContext.Server.HtmlEncode"
        };

        private static readonly DiagnosticDescriptor Rule = LocaleUtil.GetDescriptor(DiagnosticId);

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(Rule);

        public override void Initialize(AnalysisContext context)
        {
            context.RegisterSyntaxNodeAction(VisitMethodsCSharp,      CSharp.SyntaxKind.ClassDeclaration);
            context.RegisterSyntaxNodeAction(VisitMethodsVisualBasic, VB.SyntaxKind.ClassBlock);
        }

        private void VisitMethodsCSharp(SyntaxNodeAnalysisContext ctx)
        {
            var node = ctx.Node as CSharpSyntax.ClassDeclarationSyntax;

            if (node == null)
                return;

            // Ensures that the analyzed class has a dependency to Controller
            if (!node.DescendantNodesAndSelf()
                     .OfType<CSharpSyntax.BaseListSyntax>()
                     .Any(childrenNode => childrenNode.ToString().Contains("Controller")))
            {
                return;
            }

            var methodsWithParameters = node.DescendantNodesAndSelf()
                                            .OfType<CSharpSyntax.MethodDeclarationSyntax>()
                                            .Where(method => method.ParameterList.Parameters.Any())
                                            .Where(method => method.Modifiers.ToString().Equals("public"))
                                            .Where(method => method.ReturnType.ToString().Equals("string"));

            foreach (CSharpSyntax.MethodDeclarationSyntax method in methodsWithParameters)
            {
                SyntaxList<CSharpSyntax.StatementSyntax> methodStatements  = method.Body.Statements;
                var methodInvocations = method.DescendantNodes()
                                              .OfType<CSharpSyntax.InvocationExpressionSyntax>()
                                              .ToArray();

                if (!methodStatements.Any())
                    continue;

                DataFlowAnalysis flow = ctx.SemanticModel.AnalyzeDataFlow(methodStatements.First(),
                                                                          methodStatements.Last());

                // Returns from the Data Flow Analysis of sensible data 
                // Sensible data is: Data passed as a parameter that is also returned as is by the method
                var sensibleVariables  = flow.DataFlowsIn.Union(flow.VariablesDeclared.Except(flow.AlwaysAssigned))
                                                         .Union(flow.WrittenInside)
                                                         .Intersect(flow.WrittenOutside)
                                                         .ToArray();

                if (!sensibleVariables.Any())
                    continue;

                foreach (ISymbol sensibleVariable in sensibleVariables)
                {
                    bool sensibleVariableIsEncoded = false;
                    foreach (CSharpSyntax.InvocationExpressionSyntax methodInvocation in methodInvocations)
                    {
                        var arguments = methodInvocation.ArgumentList.Arguments;
                        if (!arguments.Any())
                            continue;

                        if (arguments.First().ToString().Contains(sensibleVariable.Name))
                        {
                            sensibleVariableIsEncoded = true;
                        }
                    }

                    if (!sensibleVariableIsEncoded)
                    {
                        ctx.ReportDiagnostic(Diagnostic.Create(Rule, method.GetLocation()));
                    }
                }
            }
        }

        // TODO: Drink a lot of coffee and make this generic. 
        // Problem #1: So many language specific sytax nodes (why o why are they implemented like this).
        // Problem #2: Literal strings are different.
        // Perhaps there could be a way to swap the VB/C# syntax types about. 
        // Maybe make a wrapper around each of the diffferent common syntax types. :@

        private void VisitMethodsVisualBasic(SyntaxNodeAnalysisContext ctx)
        {
            var node = ctx.Node as VBSyntax.ClassBlockSyntax;

            if (node == null)
                return;

            // Ensures that the analyzed class has a dependency to Controller
            if (!node.DescendantNodesAndSelf()
                     .OfType<VBSyntax.InheritsOrImplementsStatementSyntax>()
                     .Any(childrenNode => childrenNode.ToString().Contains("Controller")))
            {
                return;
            }

            var methodsWithParameters = node.DescendantNodesAndSelf()
                                            .OfType<VBSyntax.MethodBlockSyntax>()
                                            .Where(method =>
                                                       method.SubOrFunctionStatement.ParameterList.Parameters.Any())
                                            .Where(method => method
                                                             .SubOrFunctionStatement
                                                             .Modifiers
                                                             .ToString()
                                                             .Equals("Public"))
                                            .Where(method => method.SubOrFunctionStatement
                                                                   .AsClause
                                                                   ?.Type
                                                                   .ToString()
                                                                   .Equals("String") ?? false);

            foreach (VBSyntax.MethodBlockSyntax method in methodsWithParameters)
            {
                SyntaxList<VBSyntax.StatementSyntax> methodStatements  = method.Statements;
                var methodInvocations = method.DescendantNodes()
                                              .OfType<VBSyntax.InvocationExpressionSyntax>()
                                              .ToArray();

                if (!methodStatements.Any())
                    continue;

                DataFlowAnalysis flow = ctx.SemanticModel.AnalyzeDataFlow(methodStatements.First(),
                                                                          methodStatements.Last());

                // Returns from the Data Flow Analysis of sensible data 
                // Sensible data is: Data passed as a parameter that is also returned as is by the method
                var sensibleVariables = flow.DataFlowsIn.Union(flow.VariablesDeclared.Except(flow.AlwaysAssigned))
                                                        .Union(flow.WrittenInside)
                                                        .Intersect(flow.WrittenOutside)
                                                        .ToArray();

                if (!sensibleVariables.Any())
                    continue;

                foreach (ISymbol sensibleVariable in sensibleVariables)
                {
                    bool sensibleVariableIsEncoded = false;
                    foreach (VBSyntax.InvocationExpressionSyntax methodInvocation in methodInvocations)
                    {
                        var arguments = methodInvocation.ArgumentList.Arguments;
                        if (!arguments.Any())
                            continue;

                        if (arguments.First().ToString().Contains(sensibleVariable.Name))
                        {
                            sensibleVariableIsEncoded = true;
                        }
                    }

                    if (!sensibleVariableIsEncoded)
                    {
                        ctx.ReportDiagnostic(Diagnostic.Create(Rule, method.GetLocation()));
                    }
                }
            }
        }
    }
}
