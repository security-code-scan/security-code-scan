using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using VB = Microsoft.CodeAnalysis.VisualBasic;
using CSharp = Microsoft.CodeAnalysis.CSharp;
using CSharpSyntax = Microsoft.CodeAnalysis.CSharp.Syntax;
using VBSyntax = Microsoft.CodeAnalysis.VisualBasic.Syntax;

using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Collections.Immutable;

using RoslynSecurityGuard.Analyzers.Locale;


namespace RoslynSecurityGuard.Analyzers
{
    [DiagnosticAnalyzer(LanguageNames.CSharp, LanguageNames.VisualBasic)]
    public class XssPreventionAnalyzer : DiagnosticAnalyzer
    {
        public const string DiagnosticId = "SG0029";

        private List<string> encodingMethods = new List<string>() { "HtmlEncoder.Default.Encode", "HttpContext.Server.HtmlEncode" };

        private static DiagnosticDescriptor Rule = LocaleUtil.GetDescriptor(DiagnosticId);

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(Rule);

        public override void Initialize(AnalysisContext context)
        {
            context.RegisterSyntaxNodeAction(VisitMethodsCSharp, CSharp.SyntaxKind.ClassDeclaration);
            context.RegisterSyntaxNodeAction(VisitMethodsVisualBasic, VB.SyntaxKind.ClassBlock);
        }

        private void VisitMethodsCSharp(SyntaxNodeAnalysisContext ctx)
        {
            CSharpSyntax.ClassDeclarationSyntax node = ctx.Node as CSharpSyntax.ClassDeclarationSyntax;

            if (node == null) return;

            // Ensures that the analyzed class has a dependency to Controller
            if (node
                .DescendantNodesAndSelf()
                .OfType<CSharpSyntax.BaseListSyntax>()
                .Count(childrenNode => childrenNode.ToString().Contains("Controller"))
                .Equals(0))
            { return; }

            IEnumerable<CSharpSyntax.MethodDeclarationSyntax> methodsWithParameters = node.DescendantNodesAndSelf()
                .OfType<CSharpSyntax.MethodDeclarationSyntax>()
                .Where(method => !method.ParameterList.Parameters.Count.Equals(0))
                .Where(method => method.Modifiers.ToString().Equals("public"))
                .Where(method => method.ReturnType.ToString().Equals("string"));

            foreach (CSharpSyntax.MethodDeclarationSyntax method in methodsWithParameters)
            {
                SyntaxList<CSharpSyntax.StatementSyntax> methodStatements = method.Body.Statements;
                IEnumerable<CSharpSyntax.InvocationExpressionSyntax> methodInvocations = method.DescendantNodes().OfType<CSharpSyntax.InvocationExpressionSyntax>();

                if (!methodStatements.Count.Equals(0))
                {
                    DataFlowAnalysis flow = ctx.SemanticModel.AnalyzeDataFlow(methodStatements.First(), methodStatements.Last());

                    // Returns from the Data Flow Analysis of sensible data 
                    // Sensible data is: Data passed as a parameter that is also returned as is by the method
                    IEnumerable<ISymbol> sensibleVariables = flow.DataFlowsIn.Union(flow.VariablesDeclared.Except(flow.AlwaysAssigned))
                                                                .Union(flow.WrittenInside)
                                                                .Intersect(flow.WrittenOutside);

                    if (!sensibleVariables.Count().Equals(0))
                    {
                        foreach (ISymbol sensibleVariable in sensibleVariables)
                        {
                            bool sensibleVariableIsEncoded = false;
                            foreach (CSharpSyntax.InvocationExpressionSyntax methodInvocation in methodInvocations)
                            {
                                SeparatedSyntaxList<CSharpSyntax.ArgumentSyntax> arguments = methodInvocation.ArgumentList.Arguments;
                                if (!arguments.Count.Equals(0))
                                {
                                    if (arguments.First().ToString().Contains(sensibleVariable.Name))
                                    {
                                        sensibleVariableIsEncoded = true;
                                    }
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

        // TODO: Drink a lot of coffee and make this generic. 
        // Problem #1: So many language specific sytax nodes (why o why are they implemented like this).
        // Problem #2: Literal strings are different.
        // Perhaps there could be a way to swap the VB/C# syntax types about. 
        // Maybe make a wrapper around each of the diffferent common syntax types. :@

        private void VisitMethodsVisualBasic(SyntaxNodeAnalysisContext ctx)
        {
            VBSyntax.ClassBlockSyntax node = ctx.Node as VBSyntax.ClassBlockSyntax;

            if (node == null) return;

            // Ensures that the analyzed class has a dependency to Controller
            if (node
                .DescendantNodesAndSelf()
                .OfType<VBSyntax.InheritsOrImplementsStatementSyntax>()
                .Count(childrenNode => childrenNode.ToString().Contains("Controller"))
                .Equals(0))
            { return; }

            IEnumerable<VBSyntax.MethodBlockSyntax> methodsWithParameters = node.DescendantNodesAndSelf()
                .OfType<VBSyntax.MethodBlockSyntax>()
                .Where(method => !method.SubOrFunctionStatement.ParameterList.Parameters.Count.Equals(0))
                .Where(method => method.SubOrFunctionStatement.Modifiers.ToString().Equals("Public"))
                .Where(method => method.SubOrFunctionStatement.AsClause?.Type.ToString().Equals("String") ?? false);

            foreach (VBSyntax.MethodBlockSyntax method in methodsWithParameters)
            {
                SyntaxList<VBSyntax.StatementSyntax> methodStatements = method.Statements;
                IEnumerable<VBSyntax.InvocationExpressionSyntax> methodInvocations = method.DescendantNodes().OfType<VBSyntax.InvocationExpressionSyntax>();

                if (!methodStatements.Count.Equals(0))
                {
                    DataFlowAnalysis flow = ctx.SemanticModel.AnalyzeDataFlow(methodStatements.First(), methodStatements.Last());

                    // Returns from the Data Flow Analysis of sensible data 
                    // Sensible data is: Data passed as a parameter that is also returned as is by the method
                    IEnumerable<ISymbol> sensibleVariables = flow.DataFlowsIn.Union(flow.VariablesDeclared.Except(flow.AlwaysAssigned))
                                                                .Union(flow.WrittenInside)
                                                                .Intersect(flow.WrittenOutside);

                    if (!sensibleVariables.Count().Equals(0))
                    {
                        foreach (ISymbol sensibleVariable in sensibleVariables)
                        {
                            bool sensibleVariableIsEncoded = false;
                            foreach (VBSyntax.InvocationExpressionSyntax methodInvocation in methodInvocations)
                            {
                                SeparatedSyntaxList<VBSyntax.ArgumentSyntax> arguments = methodInvocation.ArgumentList.Arguments;
                                if (!arguments.Count.Equals(0))
                                {
                                    if (arguments.First().ToString().Contains(sensibleVariable.Name))
                                    {
                                        sensibleVariableIsEncoded = true;
                                    }
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
    }
}
