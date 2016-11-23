using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Diagnostics;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Collections.Immutable;
using RoslynSecurityGuard.Analyzers.Locale;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using System.Collections;

namespace RoslynSecurityGuard.Analyzers
{
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public class XssPreventionAnalyzer : DiagnosticAnalyzer
    {
        public const string DiagnosticId = "SG0025";

        private List<string> encodingMethods = new List<string>() { "HtmlEncoder.Default.Encode", "HttpContext.Server.HtmlEncode" };

        private static DiagnosticDescriptor Rule = LocaleUtil.GetDescriptor(DiagnosticId);

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(Rule);

        public override void Initialize(AnalysisContext context)
        {
            context.RegisterSyntaxNodeAction(VisitMethods, SyntaxKind.ClassDeclaration);
        }

        private void VisitMethods(SyntaxNodeAnalysisContext ctx)
        {
            ClassDeclarationSyntax node = ctx.Node as ClassDeclarationSyntax;

            if (node == null) return;

            // Ensures that the analyzed class has a dependency to Controller
            if (node.DescendantNodesAndSelf()
                .OfType<BaseListSyntax>()
                .Where(childrenNode => childrenNode.ToString().Contains("Controller"))
                .Count()
                .Equals(0))
            { return; }

            IEnumerable<MethodDeclarationSyntax> methodsWithParameters = node.DescendantNodesAndSelf()
                .OfType<MethodDeclarationSyntax>()
                .Where(method => !method.ParameterList.Parameters.Count().Equals(0));

            foreach (MethodDeclarationSyntax method in methodsWithParameters)
            {
                SyntaxList<StatementSyntax> methodStatements = method.Body.Statements;
                IEnumerable<InvocationExpressionSyntax> methodInvocations = method.DescendantNodes().OfType<InvocationExpressionSyntax>();

                if (!methodStatements.Count().Equals(0))
                {
                    DataFlowAnalysis flow = ctx.SemanticModel.AnalyzeDataFlow(methodStatements.First(), methodStatements.Last());

                    // Returns from the Data Flow Analysis of sensible data 
                    // Sensible data is: Data passed as a parameter that is also returned as is by the method
                    IEnumerable<ISymbol> sensibleVariables = flow.DataFlowsIn.Union(flow.VariablesDeclared.Except(flow.AlwaysAssigned))
                                                                .Union(flow.WrittenInside)
                                                                .Intersect(flow.WrittenOutside);
                                          
                    // Ensures that the sensible data does not have any encoding
                    if (!sensibleVariables.Count().Equals(0))
                    {
                        foreach (ISymbol sensibleVariable in sensibleVariables)
                        {
                            bool sensibleVariableIsEncoded = false;
                            foreach (InvocationExpressionSyntax methodInvocation in methodInvocations)
                            {
                                SeparatedSyntaxList<ArgumentSyntax> arguments = methodInvocation.ArgumentList.Arguments;
                                if (!arguments.Count().Equals(0))
                                {
                                    if (arguments.First().ToString().Contains(sensibleVariable.Name.ToString()))
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
