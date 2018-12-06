using System.Collections.Generic;
using System.Collections.Immutable;
using System.Composition;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CodeActions;
using Microsoft.CodeAnalysis.CodeFixes;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SecurityCodeScan.Analyzers;
using SecurityCodeScan.Analyzers.Utils;
using SF = Microsoft.CodeAnalysis.CSharp.SyntaxFactory;

namespace SecurityCodeScan.CodeFixes
{
    [ExportCodeFixProvider(LanguageNames.CSharp, Name = nameof(InsecureCookieCodeFixProvider)), Shared]
    public class CsrfTokenCodeFixProvider : CodeFixProvider
    {
        private const          string                 CreateAnnotationTitle = "Add [ValidateAntiForgeryToken] validation";
        public sealed override ImmutableArray<string> FixableDiagnosticIds { get; } = ImmutableArray.Create(CsrfTokenDiagnosticAnalyzer.DiagnosticId);

        public sealed override FixAllProvider GetFixAllProvider()
        {
            return WellKnownFixAllProviders.BatchFixer;
        }

        public sealed override Task RegisterCodeFixesAsync(CodeFixContext context)
        {
            // TODO: Replace the following code with your own analysis, generating a CodeAction for each fix to suggest
            var diagnostic = context.Diagnostics.First();

            context.RegisterCodeFix(
                CodeAction.Create(
                    title: CreateAnnotationTitle,
                    createChangedDocument: c => AddAnnotation(context.Document, diagnostic, c),
                    equivalenceKey: CreateAnnotationTitle),
                diagnostic);

            return Task.FromResult(0);
        }

        private async Task<Document> AddAnnotation(Document          document,
                                                   Diagnostic        diagnostic,
                                                   CancellationToken cancellationToken)
        {
            var root = await document.GetSyntaxRootAsync().ConfigureAwait(false);
            var methodDeclaration = root.FindToken(diagnostic.Location.SourceSpan.Start).Parent
                                                                                        .AncestorsAndSelf()
                                                                                        .OfType<MethodDeclarationSyntax>()
                                                                                        .First();
            if (methodDeclaration == null)
            {
                return document;
            }

            var attributesList = methodDeclaration.AttributeLists[0];

            var annotationValidate = SF.AttributeList()
                                       .AddAttributes(SF.Attribute(SF.IdentifierName("ValidateAntiForgeryToken")))
                                       .WithLeadingTrivia(CodeFixUtil.KeepLastLine(attributesList.GetLeadingTrivia()));

            var nodes = new List<SyntaxNode> { annotationValidate };

            var newRoot = root.InsertNodesAfter(attributesList, nodes);
            return document.WithSyntaxRoot(newRoot);
        }
    }
}
