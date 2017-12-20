using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;

using RoslynSecurityGuard.Analyzers.Locale;
using RoslynSecurityGuard.Analyzers.Utils;
using VB = Microsoft.CodeAnalysis.VisualBasic;
using CSharp = Microsoft.CodeAnalysis.CSharp;
using CSharpSyntax = Microsoft.CodeAnalysis.CSharp.Syntax;
using VBSyntax = Microsoft.CodeAnalysis.VisualBasic.Syntax;


namespace RoslynSecurityGuard.Analyzers
{
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public class OutputCacheAnnotationAnalyzer : DiagnosticAnalyzer
    {
        public const string DiagnosticId = "SG0019";
        private static readonly DiagnosticDescriptor Rule = LocaleUtil.GetDescriptor(DiagnosticId);
        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(Rule);

        public override void Initialize(AnalysisContext context)
        {
            context.RegisterSyntaxNodeAction(VisitClass, CSharp.SyntaxKind.ClassDeclaration);
            context.RegisterSyntaxNodeAction(VisitClass, VB.SyntaxKind.ClassBlock);
        }

        private bool HasOutputCacheAttribute(ISymbol symbol, ref int duration, bool method)
        {
            int d = duration;

            Func<AttributeData, bool> condition = attributeData =>
            {
                if (attributeData.AttributeClass.ToString() != "System.Web.Mvc.OutputCacheAttribute")
                    return false;
                var durationArgument = attributeData.NamedArguments.FirstOrDefault(x => x.Key == "Duration");
                if (durationArgument.Equals(default(KeyValuePair<string, TypedConstant>)))
                    d = int.MaxValue;
                else
                    d = (int) durationArgument.Value.Value;

                return true;
            };

            var ret = method ? ((IMethodSymbol)symbol).HasDerivedMethodAttribute(condition) : ((ITypeSymbol)symbol).HasDerivedClassAttribute(condition);
            duration = d;
            return ret;
        }

        private void VisitClass(SyntaxNodeAnalysisContext ctx)
        {
            SyntaxNode node;
            SyntaxList<SyntaxNode> members;
            if (ctx.Node.Language == LanguageNames.CSharp)
            {
                node = ctx.Node as CSharpSyntax.ClassDeclarationSyntax;
                if (node == null) return; //Not the expected node type
                members = ((CSharpSyntax.ClassDeclarationSyntax)node).Members;
            }
            else {
                node = ctx.Node as VBSyntax.ClassBlockSyntax;
                if (node == null) return; //Not the expected node type
                members = ((VBSyntax.ClassBlockSyntax)node).Members;
            }

            var classSymbol = (ITypeSymbol)ctx.SemanticModel.GetDeclaredSymbol(node);

            bool classHasAuthAnnotation = classSymbol.HasDerivedClassAttribute(attributeData => attributeData.AttributeClass.ToString() == "System.Web.Mvc.AuthorizeAttribute");
            int classCacheDuration = 0;
            bool classHasCacheAnnotation = HasOutputCacheAttribute(classSymbol, ref classCacheDuration, method: false);

            foreach (SyntaxNode member in members)
            {
                SyntaxNode method;
                if (ctx.Node.Language == LanguageNames.CSharp)
                {
                    method = member as CSharpSyntax.MethodDeclarationSyntax;
                }
                else
                {
                    method = member as VBSyntax.MethodBlockSyntax;
                }
                if (method == null)
                    continue;

                var methodSymbol = (IMethodSymbol)ctx.SemanticModel.GetDeclaredSymbol(method);
                if (methodSymbol.DeclaredAccessibility != Accessibility.Public)
                    continue;

                bool methodHasAuthAnnotation = methodSymbol.HasDerivedMethodAttribute(attributeData => attributeData.AttributeClass.ToString() == "System.Web.Mvc.AuthorizeAttribute");
                int methodCacheDuration = 0;
                bool methodHasCacheAnnotation = HasOutputCacheAttribute(methodSymbol, ref methodCacheDuration, method: true);

                bool hasAuth = classHasAuthAnnotation || methodHasAuthAnnotation;
                bool hasCache = methodHasCacheAnnotation ? methodCacheDuration > 0 : (classHasCacheAnnotation && classCacheDuration > 0);

                if (hasAuth && hasCache)
                {
                    ctx.ReportDiagnostic(Diagnostic.Create(Rule, method.GetLocation()));
                }
            }
        }
    }
}
