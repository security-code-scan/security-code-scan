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

namespace RoslynSecurityGuard.Analyzers
{
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public class CsrfTokenAnalyzer : DiagnosticAnalyzer
    {
        public const string DiagnosticId = "SG0016";
        private static DiagnosticDescriptor Rule = LocaleUtil.GetDescriptor(DiagnosticId);
        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(Rule);

        //99% of the occurences will be HttpPost.. but here are some additionnal HTTP methods
        //https://msdn.microsoft.com/en-us/library/system.web.mvc.actionmethodselectorattribute(v=vs.118).aspx
        private List<string> MethodsHttp = new List<string>() { "HttpPost", "HttpPut", "HttpDelete", "HttpPatch" };

        public override void Initialize(AnalysisContext context)
        {
            context.RegisterSyntaxNodeAction(VisitMethods, SyntaxKind.MethodDeclaration);
        }

        private void VisitMethods(SyntaxNodeAnalysisContext ctx)
        {
            var node = ctx.Node as MethodDeclarationSyntax;

            if (node == null)
            { //Not the expected node type
                return;
            }

            bool hasActionMethod = false;
            bool hasValidateAntiForgeryToken = false;

            //Iterating over the list of annotation for a given method
            foreach (var attributesInlined in node.AttributeLists) {
                if (attributesInlined.Attributes.Count == 0) continue; //Bound check .. Unlikely to happens

                List<string> attributesList = getAttributesForMethod(node);

                //Extract the annotation identifier
                //var identifier = attributesInlined.Attributes[0].Name as IdentifierNameSyntax;
                foreach (var attribute in attributesList)
                {
                    if (MethodsHttp.Contains(attribute))
                    {
                        hasActionMethod = true;
                    }
                    else if (attribute.Equals("ValidateAntiForgeryToken"))
                    {
                        hasValidateAntiForgeryToken = true;
                    }
                }
            }

            if (hasActionMethod && !hasValidateAntiForgeryToken)
            {
                ctx.ReportDiagnostic(Diagnostic.Create(Rule, node.GetLocation()));
            }
        }
        private List<string> getAttributesForMethod(MethodDeclarationSyntax node)
        {
            List<string> attributesList = new List<string>();

            if(node.AttributeLists != null)
            {
                foreach (AttributeListSyntax attributeList in node.AttributeLists)
                { 

                    if (attributeList.Attributes != null)
                    {
                        foreach (AttributeSyntax attribute in attributeList.Attributes)
                        {
                            attributesList.Add(attribute.Name.GetText().ToString());
                        }
                    }
                }
            }
            return attributesList;
        }
    }
}
