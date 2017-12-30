using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CodeActions;
using Microsoft.CodeAnalysis.CodeFixes;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SecurityCodeScan.Analyzers;
using SecurityCodeScan.Analyzers.Utils;
using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Composition;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using SF = Microsoft.CodeAnalysis.CSharp.SyntaxFactory;

namespace SecurityCodeScan.CodeFixes
{
    [ExportCodeFixProvider(LanguageNames.CSharp, Name = nameof(InsecureCookieCodeFixProvider)), Shared]
    public class CsrfTokenCodeFixProvider : CodeFixProvider
    {
        private const string CreateAnnotationTitle = "Add [ValidateAntiForgeryToken] validation";
        public sealed override ImmutableArray<string> FixableDiagnosticIds => ImmutableArray.Create(CsrfTokenAnalyzer.DiagnosticId);


        public sealed override FixAllProvider GetFixAllProvider()
        {
            return WellKnownFixAllProviders.BatchFixer;
        }

        public sealed override async Task RegisterCodeFixesAsync(CodeFixContext context)
        {
            var root = await context.Document.GetSyntaxRootAsync(context.CancellationToken).ConfigureAwait(false);

            // TODO: Replace the following code with your own analysis, generating a CodeAction for each fix to suggest
            var diagnostic = context.Diagnostics.First();


            context.RegisterCodeFix(
                CodeAction.Create(
                    title: CreateAnnotationTitle,
                    createChangedDocument: c => AddAnnotation(context.Document, diagnostic, c),
                    equivalenceKey: CreateAnnotationTitle),
                diagnostic);

        }
        
        private async Task<Document> AddAnnotation(Document document, Diagnostic diagnostic, CancellationToken cancellationToken)
        {
            var root = await document.GetSyntaxRootAsync(cancellationToken).ConfigureAwait(false);
            var highlightedNode = root.FindToken(diagnostic.Location.SourceSpan.Start).Parent;

            var methodDeclaration = CodeFixUtil.GetParentNode(highlightedNode, typeof(MethodDeclarationSyntax)) as MethodDeclarationSyntax;
            var attributesList = methodDeclaration.AttributeLists[0] as AttributeListSyntax;

            if (methodDeclaration == null) return document;

            var annotationValidate = SF.AttributeList()
                    .AddAttributes(SF.Attribute(SF.IdentifierName("ValidateAntiForgeryToken")))
                    .WithLeadingTrivia(CodeFixUtil.KeepLastLine(attributesList.GetLeadingTrivia()));

            var nodes = new List<SyntaxNode>();
            nodes.Add(annotationValidate);

            var newRoot = root.InsertNodesAfter(attributesList, nodes);
            return document.WithSyntaxRoot(newRoot);
        }


    }
}
